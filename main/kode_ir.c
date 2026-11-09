/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_ir.c
 * @brief The Kode Dot's infrared block (IO24 out, IO23 in), served to the
 *        host over peer data (kir_wire.h): one task owns the RMT.
 */
#include "kode_ir.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/rmt_rx.h"
#include "driver/rmt_tx.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_hosted_peer_data.h"
#include "kir_wire.h"

#define TAG "kode_ir"

#define IR_PIN_TX              24        /**< IO24: the emitters, active high. */
#define IR_PIN_RX              23        /**< IO23: the TSOP75338, active low. */

#define IR_RESOLUTION_HZ       1000000U  /**< One RMT tick is one microsecond.  */
#define IR_MEM_BLOCK_SYMBOLS   64U       /**< RMT memory per channel, symbols.  */
#define IR_TX_QUEUE_DEPTH      4U        /**< RMT transmissions queued.         */
/** @brief Carrier duty of a mark: the most a TSOP-class receiver is tuned for;
 *         the peak current is set by the resistors, not by this. */
#define IR_CARRIER_DUTY        0.50F
#define IR_RX_MIN_NS           1250U     /**< A shorter pulse is a glitch.      */
#define IR_RX_MAX_NS           12000000U /**< A longer level ends the capture.  */
#define IR_DURATION_MAX        0x7FFFU   /**< An RMT symbol's duration field.   */
#define IR_DURATION_MIN        1U        /**< A mark of 0 would end the frame.  */
#define IR_PRESENT_DRIVE_US    1000U     /**< The presence probe pulls this long. */
#define IR_PRESENT_SETTLE_US   100U      /**< Then waits this long to read.     */
#define IR_IDLE_SETTLE_US      50U       /**< Pulls off, then this before a read. */
/** @brief The longest frame is 256 symbols of 65 ms; nothing real is near it. */
#define IR_TX_DONE_MS          2000

#define IR_TASK_STACK          4096U     /**< Bytes.                            */
#define IR_TASK_PRIO           5U        /**< FreeRTOS priority.                */
#define IR_QUEUE_DEPTH         4U        /**< Jobs waiting for the task.        */

/** @brief What travels to the task: a request from the host, or the receive
 *         interrupt saying a capture is complete. */
typedef struct {
    uint8_t *req;       /**< A heap copy of the request; NULL for a capture. */
    size_t   len;       /**< Its length.                                     */
    size_t   captured;  /**< Symbols received, when @c req is NULL.          */
    bool     park;      /**< Close the block (kode_ir_park()).               */
} ir_job_t;

static QueueHandle_t        s_queue;
static rmt_channel_handle_t s_tx;
static rmt_channel_handle_t s_rx;
static rmt_encoder_handle_t s_enc;
static uint32_t             s_carrier_hz;
static bool                 s_open;
static volatile bool        s_dropped;

static rmt_symbol_word_t s_rx_raw[KIR_MAX_SYMBOLS];
static rmt_symbol_word_t s_tx_raw[KIR_MAX_SYMBOLS];
/** @brief The capture event as it goes out: header, then the symbols. */
static uint8_t s_evt[sizeof(kir_capture_t) + (KIR_MAX_SYMBOLS * sizeof(kir_symbol_t))];

/** @brief Receive interrupt: tell the task how much arrived, and leave. */
static bool ir_recv_done(rmt_channel_handle_t chan,
                         const rmt_rx_done_event_data_t *edata, void *ctx)
{
    BaseType_t woken = pdFALSE;
    ir_job_t   job   = { .req = NULL, .len = 0U, .captured = edata->num_symbols };

    (void)chan;
    (void)ctx;
    if ( xQueueSendFromISR(s_queue, &job, &woken) != pdTRUE )
    {
        s_dropped = true;   /* said by the task; an ISR does not log */
    }
    return (woken == pdTRUE);
}

/**
 * @brief Close whatever of the block is open.
 *
 * Disabled first, whatever state each channel is in: the driver refuses to
 * delete a channel that is enabled, and this chip has two of each, so one
 * leaked pair is every later open failing for the boot.
 */
static void ir_close(void)
{
    if ( NULL != s_tx )
    {
        (void)rmt_disable(s_tx);
    }
    if ( NULL != s_rx )
    {
        (void)rmt_disable(s_rx);
    }
    if ( NULL != s_enc )
    {
        (void)rmt_del_encoder(s_enc);
        s_enc = NULL;
    }
    if ( NULL != s_tx )
    {
        (void)rmt_del_channel(s_tx);
        s_tx = NULL;
    }
    if ( NULL != s_rx )
    {
        (void)rmt_del_channel(s_rx);
        s_rx = NULL;
    }
    s_open = false;
}

/**
 * @brief Open both channels, on the first request that needs them.
 *
 * @return true when the block is open.
 */
static bool ir_open(void)
{
    if ( s_open )
    {
        return true;
    }

    rmt_rx_channel_config_t const rx_cfg = {
        .gpio_num          = IR_PIN_RX,
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .resolution_hz     = IR_RESOLUTION_HZ,
        .mem_block_symbols = IR_MEM_BLOCK_SYMBOLS,
    };
    rmt_tx_channel_config_t const tx_cfg = {
        .gpio_num          = IR_PIN_TX,
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .resolution_hz     = IR_RESOLUTION_HZ,
        .mem_block_symbols = IR_MEM_BLOCK_SYMBOLS,
        .trans_queue_depth = IR_TX_QUEUE_DEPTH,
    };
    rmt_rx_event_callbacks_t const rx_cbs = { .on_recv_done = ir_recv_done };
    rmt_copy_encoder_config_t const enc_cfg = { };

    if ( (rmt_new_rx_channel(&rx_cfg, &s_rx) != ESP_OK)
        || (rmt_rx_register_event_callbacks(s_rx, &rx_cbs, NULL) != ESP_OK)
        || (rmt_new_tx_channel(&tx_cfg, &s_tx) != ESP_OK)
        || (rmt_new_copy_encoder(&enc_cfg, &s_enc) != ESP_OK)
        || (rmt_enable(s_rx) != ESP_OK)
        || (rmt_enable(s_tx) != ESP_OK) )
    {
        ESP_LOGE(TAG, "the RMT would not open on IO%d / IO%d", IR_PIN_TX, IR_PIN_RX);
        ir_close();
        return false;
    }
    s_carrier_hz = 0U;
    s_open = true;
    ESP_LOGI(TAG, "open: TX IO%d, RX IO%d", IR_PIN_TX, IR_PIN_RX);
    return true;
}

/** @brief Send a three-byte status event. */
static void ir_send_status(uint8_t evt, uint8_t status)
{
    kir_status_t const s = { .evt = evt, .version = KIR_WIRE_VERSION, .status = status };

    (void)esp_hosted_send_custom_data(KIR_MSG_EVT, (const uint8_t *)&s, sizeof(s));
}

/** @brief Send a level event. */
static void ir_send_level(uint8_t op, uint8_t status, bool high)
{
    kir_level_t l = {
        .evt = KIR_EVT_LEVEL, .version = KIR_WIRE_VERSION, .op = op,
        .status = status, .high = 0U,
    };

    if ( high )
    {
        l.high = 1U;
    }
    (void)esp_hosted_send_custom_data(KIR_MSG_EVT, (const uint8_t *)&l, sizeof(l));
}

/**
 * @brief Refuse a request in the event its sender is waiting for, so a host
 *        blocked on a reading fails at once instead of timing out.
 */
static void ir_refuse(uint8_t op, uint8_t status)
{
    if ( (KIR_REQ_IDLE == op) || (KIR_REQ_PRESENT == op) )
    {
        ir_send_level(op, status, false);
    }
    else if ( KIR_REQ_ARM == op )
    {
        ir_send_status(KIR_EVT_ARMED, status);
    }
    else
    {
        ir_send_status(KIR_EVT_SENT, status);
    }
}

/** @brief Arm the receiver for one capture. */
static bool ir_arm(void)
{
    rmt_receive_config_t const cfg = {
        .signal_range_min_ns = IR_RX_MIN_NS,
        .signal_range_max_ns = IR_RX_MAX_NS,
    };

    return (rmt_receive(s_rx, s_rx_raw, sizeof(s_rx_raw), &cfg) == ESP_OK);
}

/** @brief KIR_REQ_SEND: lay the symbols out, transmit, wait it out, say so. */
static void ir_do_send(const uint8_t *req, size_t len)
{
    kir_send_t hdr;

    if ( sizeof(hdr) > len )
    {
        ir_send_status(KIR_EVT_SENT, KIR_BAD_REQUEST);
        return;
    }
    (void)memcpy(&hdr, req, sizeof(hdr));
    if ( (0U == hdr.n) || (KIR_MAX_SYMBOLS < hdr.n) || (0U == hdr.carrier_hz)
        || ((sizeof(hdr) + ((size_t)hdr.n * sizeof(kir_symbol_t))) != len) )
    {
        ir_send_status(KIR_EVT_SENT, KIR_BAD_REQUEST);
        return;
    }

    if ( hdr.carrier_hz != s_carrier_hz )
    {
        rmt_carrier_config_t const carrier = {
            .frequency_hz = hdr.carrier_hz,
            .duty_cycle   = IR_CARRIER_DUTY,
        };
        /* The carrier belongs to a channel at rest: step it aside, change
         * it, bring it back. Once per carrier, which in practice is once. */
        if ( (rmt_disable(s_tx) != ESP_OK)
            || (rmt_apply_carrier(s_tx, &carrier) != ESP_OK)
            || (rmt_enable(s_tx) != ESP_OK) )
        {
            ESP_LOGE(TAG, "the carrier would not change to %u Hz",
                     (unsigned)hdr.carrier_hz);
            ir_close();
            ir_send_status(KIR_EVT_SENT, KIR_FAIL);
            return;
        }
        s_carrier_hz = hdr.carrier_hz;
    }

    for ( size_t i = 0U; (size_t)hdr.n > i; ++i )
    {
        kir_symbol_t sym;
        uint32_t     mark;
        uint32_t     space;

        (void)memcpy(&sym, &req[sizeof(hdr) + (i * sizeof(sym))], sizeof(sym));
        mark  = sym.mark_us;
        space = sym.space_us;
        if ( IR_DURATION_MIN > mark )
        {
            mark = IR_DURATION_MIN;
        }
        if ( IR_DURATION_MAX < mark )
        {
            mark = IR_DURATION_MAX;
        }
        /* A zero space ends the frame; the longest space says the same to a
         * receiver, in a duration the hardware will emit. */
        if ( (0U == space) || (IR_DURATION_MAX < space) )
        {
            space = IR_DURATION_MAX;
        }
        s_tx_raw[i].level0    = 1U;
        s_tx_raw[i].duration0 = (uint16_t)mark;
        s_tx_raw[i].level1    = 0U;
        s_tx_raw[i].duration1 = (uint16_t)space;
    }

    /* eot_level 0: the emitters idle dark. */
    rmt_transmit_config_t const cfg = { .loop_count = 0 };
    if ( (rmt_transmit(s_tx, s_enc, s_tx_raw, (size_t)hdr.n * sizeof(s_tx_raw[0]), &cfg) != ESP_OK)
        || (rmt_tx_wait_all_done(s_tx, IR_TX_DONE_MS) != ESP_OK) )
    {
        ir_send_status(KIR_EVT_SENT, KIR_FAIL);
        return;
    }
    ir_send_status(KIR_EVT_SENT, KIR_OK);
}

/** @brief KIR_REQ_IDLE: the line's level with both pulls off. */
static void ir_do_idle(void)
{
    (void)gpio_pullup_dis(IR_PIN_RX);
    (void)gpio_pulldown_dis(IR_PIN_RX);
    esp_rom_delay_us(IR_IDLE_SETTLE_US);
    ir_send_level(KIR_REQ_IDLE, KIR_OK, gpio_get_level(IR_PIN_RX) != 0);
}

/**
 * @brief KIR_REQ_PRESENT: pull the line down, let go, see whether it returns.
 *
 * A fitted TSOP75338 restores the line through its own pull-up within
 * microseconds; a bare pin is still low. The receive channel steps aside for
 * the probe and is re-armed after it, so a capture in flight is lost - the
 * host driver's contract says so.
 */
static void ir_do_present(void)
{
    bool high;

    if ( rmt_disable(s_rx) != ESP_OK )
    {
        ir_send_level(KIR_REQ_PRESENT, KIR_FAIL, false);
        return;
    }
    (void)gpio_set_level(IR_PIN_RX, 0);
    (void)gpio_set_direction(IR_PIN_RX, GPIO_MODE_OUTPUT);
    esp_rom_delay_us(IR_PRESENT_DRIVE_US);
    (void)gpio_pullup_dis(IR_PIN_RX);
    (void)gpio_pulldown_dis(IR_PIN_RX);
    (void)gpio_set_direction(IR_PIN_RX, GPIO_MODE_INPUT);
    esp_rom_delay_us(IR_PRESENT_SETTLE_US);
    high = (gpio_get_level(IR_PIN_RX) != 0);

    if ( (rmt_enable(s_rx) != ESP_OK) || !ir_arm() )
    {
        ir_send_level(KIR_REQ_PRESENT, KIR_FAIL, high);
        return;
    }
    ir_send_level(KIR_REQ_PRESENT, KIR_OK, high);
}

/** @brief A capture is complete: send it to the host as mark/space pairs. */
static void ir_do_capture(size_t n)
{
    kir_capture_t hdr = { .evt = KIR_EVT_CAPTURE, .version = KIR_WIRE_VERSION, .n = 0U };

    if ( KIR_MAX_SYMBOLS < n )
    {
        n = KIR_MAX_SYMBOLS;
    }
    hdr.n = (uint16_t)n;
    (void)memcpy(s_evt, &hdr, sizeof(hdr));
    /* The receiver rests high and pulls low for a mark, so the first half of
     * every recorded symbol is the mark and the second the space. */
    for ( size_t i = 0U; i < n; ++i )
    {
        kir_symbol_t const sym = {
            .mark_us  = (uint16_t)s_rx_raw[i].duration0,
            .space_us = (uint16_t)s_rx_raw[i].duration1,
        };
        (void)memcpy(&s_evt[sizeof(hdr) + (i * sizeof(sym))], &sym, sizeof(sym));
    }
    (void)esp_hosted_send_custom_data(KIR_MSG_EVT, s_evt,
                                      sizeof(hdr) + (n * sizeof(kir_symbol_t)));
}

/** @brief The task: one job at a time, for as long as the chip runs. */
static void ir_task(void *arg)
{
    ir_job_t job;

    (void)arg;
    for ( ;; )
    {
        if ( xQueueReceive(s_queue, &job, portMAX_DELAY) != pdTRUE )
        {
            continue;
        }
        if ( s_dropped )
        {
            s_dropped = false;
            ESP_LOGW(TAG, "a capture was dropped: the job queue was full");
        }
        if ( job.park )
        {
            ir_close();
            continue;
        }
        if ( NULL == job.req )
        {
            ir_do_capture(job.captured);
            continue;
        }

        uint8_t const op = job.req[0];
        uint8_t       version = 0U;

        if ( 1U < job.len )
        {
            version = job.req[1];
        }

        if ( KIR_WIRE_VERSION != version )
        {
            ESP_LOGW(TAG, "request %u speaks wire version %u, not %u",
                     (unsigned)op, (unsigned)version, (unsigned)KIR_WIRE_VERSION);
            ir_refuse(op, KIR_BAD_REQUEST);
        }
        else if ( !ir_open() )
        {
            ir_refuse(op, KIR_FAIL);
        }
        else if ( KIR_REQ_SEND == op )
        {
            ir_do_send(job.req, job.len);
        }
        else if ( KIR_REQ_ARM == op )
        {
            if ( ir_arm() )
            {
                ir_send_status(KIR_EVT_ARMED, KIR_OK);
            }
            else
            {
                ir_send_status(KIR_EVT_ARMED, KIR_FAIL);
            }
        }
        else if ( KIR_REQ_IDLE == op )
        {
            ir_do_idle();
        }
        else if ( KIR_REQ_PRESENT == op )
        {
            ir_do_present();
        }
        else
        {
            ESP_LOGW(TAG, "unknown request %u", (unsigned)op);
        }
        free(job.req);
    }
}

/**
 * @brief A request arrived. esp-hosted's receive thread: copy it and leave.
 */
static void ir_on_request(uint32_t msg_id, const uint8_t *data, size_t len, void *ctx)
{
    ir_job_t job = { .req = NULL, .len = len, .captured = 0U };

    (void)msg_id;
    (void)ctx;
    if ( (NULL == data) || (0U == len) )
    {
        return;
    }
    job.req = malloc(len);
    if ( NULL == job.req )
    {
        ESP_LOGE(TAG, "no memory for a %u-byte request", (unsigned)len);
        return;
    }
    (void)memcpy(job.req, data, len);
    if ( xQueueSend(s_queue, &job, 0) != pdTRUE )
    {
        ESP_LOGW(TAG, "the request queue is full; one request is dropped");
        free(job.req);
    }
}

void kode_ir_park(void)
{
    ir_job_t job = { .req = NULL, .len = 0U, .captured = 0U, .park = true };

    if ( NULL == s_queue )
    {
        return;
    }
    if ( xQueueSend(s_queue, &job, 0) != pdTRUE )
    {
        ESP_LOGW(TAG, "the job queue is full; the block stays open");
    }
}

esp_err_t kode_ir_init(void)
{
    if ( NULL != s_queue )
    {
        return ESP_OK;
    }
    s_queue = xQueueCreate(IR_QUEUE_DEPTH, sizeof(ir_job_t));
    if ( NULL == s_queue )
    {
        return ESP_ERR_NO_MEM;
    }
    if ( xTaskCreate(ir_task, "kode_ir", IR_TASK_STACK, NULL, IR_TASK_PRIO, NULL) != pdPASS )
    {
        vQueueDelete(s_queue);
        s_queue = NULL;
        return ESP_ERR_NO_MEM;
    }
    return esp_hosted_register_custom_callback(KIR_MSG_REQ, ir_on_request, NULL);
}
