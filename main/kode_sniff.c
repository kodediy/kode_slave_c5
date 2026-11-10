/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_sniff.c
 * @brief The Wi-Fi frames service (KODE_SVC_SNIFF): listens in promiscuous
 *        mode on one channel when the host asks, counts every management and
 *        data frame it hears and sends a batch of summaries every period in
 *        which it heard one. It never transmits and never touches the
 *        station: it does not connect, disconnect or scan.
 */
#include "kode_sniff.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_hosted_peer_data.h"
#include "kode_sniff_rec.h"
#include "kode_svc.h"
#include "kode_wire.h"

#define TAG "kode_sniff"

#define KS_TASK_STACK     4096U  /**< Bytes of the task that sends the batches.      */
#define KS_TASK_PRIO      5U     /**< FreeRTOS priority, below the Wi-Fi task's.     */
#define KS_CHANNEL_MAX    177U   /**< Highest channel a START may name.              */
#define KS_FCS_LEN        4U     /**< Frame check sequence at the end of sig_len.    */
#define KS_BATCH_ALL_LEN  (sizeof(kode_hdr_t) + sizeof(kode_sniff_batch_t) \
                           + (KODE_SNIFF_BATCH_MAX * sizeof(kode_sniff_rec_t)))
                                 /**< A full batch event, header included.           */

static QueueHandle_t     s_queue;   /* records from the callback to the task    */
static SemaphoreHandle_t s_lock;    /* held while a batch is sent, and by STOP  */
static TaskHandle_t      s_task;    /* sends the batches; created by the first START */
static volatile bool     s_on;      /* promiscuous mode is on and batches may go out */
static uint8_t           s_why;     /* KODE_SNIFF_WHY_* of the last START's refusal */

/*
 * What the callback (Wi-Fi task) writes and the sending task reads and
 * clears. Four fields are taken as one snapshot, so the period's counts
 * always agree with each other; a critical section does that in a few
 * instructions and never waits inside, which an atomic per field would not.
 */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t     s_heard;   /* frames heard since START                 */
static uint16_t     s_mgmt;    /* management frames heard in this period   */
static uint16_t     s_data;    /* data frames heard in this period         */
static int8_t       s_rssi;    /* strongest level of this period           */

/** @brief The counts of a period that has just begun. Caller holds s_mux or owns the counts. */
static void counts_clear(void)
{
    s_mgmt = 0U;
    s_data = 0U;
    s_rssi = (int8_t)KODE_SNIFF_RSSI_NONE;
}

/**
 * @brief Count one frame heard.
 * @param type WIFI_PKT_MGMT or WIFI_PKT_DATA.
 * @param rssi The level it was heard at, dBm.
 */
static void count_frame(wifi_promiscuous_pkt_type_t type, int8_t rssi)
{
    portENTER_CRITICAL(&s_mux);
    s_heard++;
    if ( WIFI_PKT_MGMT == type )
    {
        if ( UINT16_MAX > s_mgmt )
        {
            s_mgmt++;
        }
    }
    else if ( UINT16_MAX > s_data )
    {
        s_data++;
    }
    else
    {
        /* saturated: the period has heard 65535 frames of this kind */
    }
    if ( rssi > s_rssi )
    {
        s_rssi = rssi;
    }
    portEXIT_CRITICAL(&s_mux);
}

/**
 * @brief The promiscuous callback, on the Wi-Fi task: count the frame, queue
 *        its record without waiting. A full queue is not an error: the counts
 *        already have the frame.
 *
 * @param buf  A wifi_promiscuous_pkt_t.
 * @param type The kind of frame; only management and data are asked for.
 */
static void on_frame(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *const pkt = (const wifi_promiscuous_pkt_t *)buf;
    kode_sniff_rec_t rec;

    if ( (NULL == pkt) || ((WIFI_PKT_MGMT != type) && (WIFI_PKT_DATA != type)) )
    {
        return;
    }
    int8_t const   rssi = (int8_t)pkt->rx_ctrl.rssi;
    uint16_t const sig  = (uint16_t)pkt->rx_ctrl.sig_len;   /* with the FCS */

    count_frame(type, rssi);
    /* The record is built from the frame without its FCS, so the head never
     * holds it; the length it carries is the one on the air. */
    if ( (KS_FCS_LEN < sig) && ksr_build(pkt->payload, (uint16_t)(sig - KS_FCS_LEN), rssi, &rec) )
    {
        rec.len = sig;
        (void)xQueueSend(s_queue, &rec, 0);
    }
}

/**
 * @brief Whether the station holds an association, and on which channel.
 * @param channel Out: the network's channel when joined, else 0.
 * @return ESP_OK when joined; ESP_ERR_WIFI_NOT_INIT or _NOT_STARTED when Wi-Fi
 *         is not up; another error when it is up and not joined.
 */
static esp_err_t station_probe(uint8_t *channel)
{
    wifi_ap_record_t ap;
    esp_err_t const  err = esp_wifi_sta_get_ap_info(&ap);

    *channel = 0U;
    if ( ESP_OK == err )
    {
        *channel = ap.primary;
    }
    return err;
}

/** @brief Whether an error says Wi-Fi is not up. */
static bool wifi_is_off(esp_err_t err)
{
    return (ESP_ERR_WIFI_NOT_INIT == err) || (ESP_ERR_WIFI_NOT_STARTED == err);
}

/**
 * @brief Write the answer's payload: the state as it is now.
 * @param out     The answer buffer.
 * @param out_len Out: the payload's bytes.
 */
static void fill_state(uint8_t *out, uint16_t *out_len)
{
    kode_sniff_state_t s;
    uint8_t            net = 0U;
    uint8_t            primary = 0U;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;

    (void)memset(&s, 0, sizeof(s));
    if ( s_on )
    {
        s.on = 1U;
    }
    if ( ESP_OK == station_probe(&net) )
    {
        s.joined  = 1U;
        s.channel = net;
    }
    else if ( ESP_OK == esp_wifi_get_channel(&primary, &second) )
    {
        s.channel = primary;
    }
    else
    {
        /* Wi-Fi is not up: no channel to report */
    }
    s.why = s_why;
    (void)memcpy(out, &s, sizeof(s));
    *out_len = (uint16_t)sizeof(s);
}

/**
 * @brief Close a request: remember why, write the state, return the status.
 * @param status  KODE_ST_*.
 * @param why     KODE_SNIFF_WHY_*.
 * @param out     The answer buffer.
 * @param out_len Out: the payload's bytes.
 * @return status.
 */
static uint8_t reply(uint8_t status, uint8_t why, uint8_t *out, uint16_t *out_len)
{
    s_why = why;
    fill_state(out, out_len);
    return status;
}

/**
 * @brief Stop, with s_lock held: no batch is being sent, and none will be.
 */
static void stop_locked(void)
{
    s_on = false;
    (void)esp_wifi_set_promiscuous(false);
    (void)xQueueReset(s_queue);
}

void kode_sniff_stop(void)
{
    if ( NULL != s_lock )
    {
        (void)xSemaphoreTake(s_lock, portMAX_DELAY);
        stop_locked();
        (void)xSemaphoreGive(s_lock);
    }
}

/**
 * @brief Send one period's batch if it heard a frame. Task context.
 *
 * Holds s_lock from the check of s_on to the end of the send, which is what
 * lets kode_sniff_stop() promise that nothing goes out after it returns.
 */
static void send_period(void)
{
    uint8_t            msg[KS_BATCH_ALL_LEN];
    kode_sniff_batch_t batch;
    uint8_t            n = 0U;
    uint8_t            primary = 0U;
    uint8_t            net = 0U;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    size_t const       first = sizeof(kode_hdr_t) + sizeof(batch);

    (void)xSemaphoreTake(s_lock, portMAX_DELAY);
    if ( s_on )
    {
        (void)memset(&batch, 0, sizeof(batch));
        portENTER_CRITICAL(&s_mux);
        batch.heard    = s_heard;
        batch.mgmt     = s_mgmt;
        batch.data     = s_data;
        batch.rssi_max = s_rssi;
        counts_clear();
        portEXIT_CRITICAL(&s_mux);

        if ( (0U != batch.mgmt) || (0U != batch.data) )
        {
            /* Each period hands over its own records, the first it heard; what
             * is left in the queue is dropped, never carried into the next. */
            while ( (KODE_SNIFF_BATCH_MAX > n)
                    && (pdTRUE == xQueueReceive(s_queue,
                                                &msg[first + ((size_t)n * sizeof(kode_sniff_rec_t))], 0)) )
            {
                n++;
            }
            (void)xQueueReset(s_queue);
            if ( ESP_OK == esp_wifi_get_channel(&primary, &second) )
            {
                batch.channel = primary;
            }
            if ( ESP_OK == station_probe(&net) )
            {
                batch.joined = 1U;
            }
            batch.count = n;

            uint16_t const pay = (uint16_t)(sizeof(batch) + ((size_t)n * sizeof(kode_sniff_rec_t)));
            kode_hdr_t const h = { KODE_WIRE_VERSION, KODE_SVC_SNIFF, KODE_SNIFF_EVT_BATCH,
                                   0U, KODE_ST_OK, 0U, pay };
            (void)memcpy(msg, &h, sizeof(h));
            (void)memcpy(&msg[sizeof(h)], &batch, sizeof(batch));
            (void)esp_hosted_send_custom_data(KODE_MSG_RSP, msg, sizeof(h) + (size_t)pay);
        }
    }
    (void)xSemaphoreGive(s_lock);
}

/**
 * @brief The task: asleep while the service is off, one period at a time
 *        while it is on.
 * @param arg Unused.
 */
static void sniff_task(void *arg)
{
    (void)arg;
    for ( ;; )
    {
        if ( s_on )
        {
            vTaskDelay(pdMS_TO_TICKS(KODE_SNIFF_PERIOD_MS));
            send_period();
        }
        else
        {
            (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        }
    }
}

/**
 * @brief Create the queue, the lock and the task, once.
 * @return true when all three exist.
 */
static bool resources_ensure(void)
{
    if ( NULL != s_task )
    {
        return true;
    }
    s_queue = xQueueCreate(KODE_SNIFF_QUEUE_LEN, sizeof(kode_sniff_rec_t));
    s_lock  = xSemaphoreCreateMutex();
    if ( (NULL != s_queue) && (NULL != s_lock)
        && (pdPASS == xTaskCreate(&sniff_task, "kode_sniff", KS_TASK_STACK, NULL, KS_TASK_PRIO, &s_task)) )
    {
        return true;
    }
    if ( NULL != s_queue )
    {
        vQueueDelete(s_queue);
        s_queue = NULL;
    }
    if ( NULL != s_lock )
    {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
    }
    s_task = NULL;
    return false;
}

/**
 * @brief Filter, callback, promiscuous mode on, then the channel; with s_lock
 *        held and the resources made.
 * @param channel The channel asked for, or 0 to stay where the radio is.
 * @param tune    Whether to change the channel (false when joined).
 * @param why     Out: KODE_SNIFF_WHY_* when this returns false.
 * @return true when listening.
 */
static bool listen_start(uint8_t channel, bool tune, uint8_t *why)
{
    wifi_promiscuous_filter_t const filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_err_t err = esp_wifi_set_promiscuous_filter(&filter);

    if ( ESP_OK == err )
    {
        err = esp_wifi_set_promiscuous_rx_cb(&on_frame);
    }
    if ( ESP_OK == err )
    {
        err = esp_wifi_set_promiscuous(true);
    }
    if ( ESP_OK != err )
    {
        /* Whatever the stack answers here, it is not in a state to listen. */
        ESP_LOGW(TAG, "promiscuous mode would not start: %s", esp_err_to_name(err));
        stop_locked();
        *why = KODE_SNIFF_WHY_WIFI_OFF;
        return false;
    }
    if ( tune )
    {
        err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if ( ESP_OK != err )
        {
            ESP_LOGW(TAG, "channel %u refused: %s", (unsigned)channel, esp_err_to_name(err));
            stop_locked();
            *why = KODE_SNIFF_WHY_CHANNEL;
            return false;
        }
    }
    /* The counts begin here, on the channel that was asked for. */
    portENTER_CRITICAL(&s_mux);
    s_heard = 0U;
    counts_clear();
    portEXIT_CRITICAL(&s_mux);
    (void)xQueueReset(s_queue);
    s_on = true;
    (void)xTaskNotifyGive(s_task);
    return true;
}

/** @brief KODE_SNIFF_START. */
static uint8_t op_start(const uint8_t *req, uint16_t len, uint8_t *out, uint16_t *out_len)
{
    kode_sniff_start_t start;
    uint8_t            net = 0U;
    uint8_t            why = KODE_SNIFF_WHY_NONE;
    esp_err_t          err;
    bool               joined;
    bool               ok;

    if ( sizeof(start) != len )
    {
        return reply(KODE_ST_BAD_REQUEST, s_why, out, out_len);
    }
    (void)memcpy(&start, req, sizeof(start));
    if ( KS_CHANNEL_MAX < start.channel )
    {
        return reply(KODE_ST_BAD_REQUEST, s_why, out, out_len);
    }

    err = station_probe(&net);
    if ( wifi_is_off(err) )
    {
        kode_sniff_stop();
        return reply(KODE_ST_REFUSED, KODE_SNIFF_WHY_WIFI_OFF, out, out_len);
    }
    joined = (ESP_OK == err);
    if ( joined && (0U != start.channel) && (net != start.channel) )
    {
        /* The station stays where it is, and what was listening goes on. */
        ESP_LOGI(TAG, "refused: the station is joined on channel %u", (unsigned)net);
        return reply(KODE_ST_REFUSED, KODE_SNIFF_WHY_JOINED, out, out_len);
    }
    if ( !resources_ensure() )
    {
        ESP_LOGW(TAG, "no room for the queue or the task");
        return reply(KODE_ST_REFUSED, KODE_SNIFF_WHY_MEMORY, out, out_len);
    }

    (void)xSemaphoreTake(s_lock, portMAX_DELAY);
    ok = listen_start(start.channel, (!joined) && (0U != start.channel), &why);
    (void)xSemaphoreGive(s_lock);
    if ( ok )
    {
        ESP_LOGI(TAG, "listening");
        return reply(KODE_ST_OK, KODE_SNIFF_WHY_NONE, out, out_len);
    }
    return reply(KODE_ST_REFUSED, why, out, out_len);
}

/** @brief KODE_SVC_SNIFF's handler (kode_svc.h). */
static uint8_t sniff_handle(uint8_t op, const uint8_t *req, uint16_t len,
                            uint8_t *out, uint16_t *out_len)
{
    uint8_t st;

    *out_len = 0U;
    if ( KODE_SNIFF_START == op )
    {
        st = op_start(req, len, out, out_len);
    }
    else if ( (KODE_SNIFF_STOP == op) && (0U == len) )
    {
        kode_sniff_stop();
        ESP_LOGI(TAG, "stopped");
        st = reply(KODE_ST_OK, KODE_SNIFF_WHY_NONE, out, out_len);
    }
    else if ( (KODE_SNIFF_STATE == op) && (0U == len) )
    {
        st = reply(KODE_ST_OK, s_why, out, out_len);
    }
    else
    {
        /* An op this service does not have, or a payload where there is none:
         * refused, and still with the state, as every answer has. */
        st = reply(KODE_ST_BAD_REQUEST, s_why, out, out_len);
    }
    return st;
}

void kode_sniff_init(void)
{
    s_why = KODE_SNIFF_WHY_NONE;
    kode_svc_register(KODE_SVC_SNIFF, &sniff_handle);
}
