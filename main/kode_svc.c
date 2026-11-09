/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_svc.c
 * @brief The KODE services' dispatcher on the C5: one task answers the
 *        requests one at a time, INFO and PARK here, the rest by handler.
 */
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"

#include "esp_hosted_peer_data.h"
#include "kode_park.h"
#include "kode_svc.h"
#include "kode_svc_frame.h"
#include "kode_wire.h"

#define TAG "kode_svc"

#define SVC_TASK_STACK   6144U   /**< Bytes.                                 */
#define SVC_TASK_PRIO    5U      /**< FreeRTOS priority.                     */
#define SVC_QUEUE_DEPTH  4U      /**< Requests waiting for the task.         */

/** @brief A request on its way to the task: a heap copy and its length. */
typedef struct {
    uint8_t *msg;   /**< The request, header first.                          */
    size_t   len;   /**< Its bytes.                                          */
} svc_job_t;

static QueueHandle_t      s_queue;
static kode_svc_handler_t s_handler[KODE_SVC_COUNT];
static volatile uint8_t   s_vault;
static volatile uint8_t   s_btkeys;
static volatile uint8_t   s_id_flags;
static volatile uint32_t  s_swaps;
static volatile uint32_t  s_misses;
static ksf_confirm_t     s_confirm;     /* this image marked valid */

void kode_svc_register(uint8_t service, kode_svc_handler_t h)
{
    if ( (KODE_SVC_SELF < service) && (KODE_SVC_COUNT > service) )
    {
        s_handler[service] = h;
    }
}

void kode_svc_set_count(uint8_t service, uint8_t value)
{
    if ( KODE_SVC_VAULT == service )
    {
        s_vault = value;
    }
    else if ( KODE_SVC_BTKEYS == service )
    {
        s_btkeys = value;
    }
    else if ( KODE_SVC_ID == service )
    {
        s_id_flags = value;
    }
    else
    {
        /* INFO has nothing else to count */
    }
}

void kode_svc_add_swap(bool known)
{
    if ( known )
    {
        s_swaps++;
    }
    else
    {
        s_misses++;
    }
}

/** @brief Send one answer: the request's header echoed, a status, a payload. */
static void answer(const kode_hdr_t *req, uint8_t status, const uint8_t *pay, uint16_t len)
{
    uint8_t *const m = malloc(sizeof(kode_hdr_t) + (size_t)len);

    if ( NULL == m )
    {
        ESP_LOGE(TAG, "no memory to answer service %u op %u",
                 (unsigned)req->service, (unsigned)req->op);
        return;
    }
    kode_hdr_t const h = { KODE_WIRE_VERSION, req->service, req->op, req->seq,
                           status, 0U, len };
    (void)memcpy(m, &h, sizeof(h));
    if ( 0U < len )
    {
        (void)memcpy(&m[sizeof(h)], pay, len);
    }
    (void)esp_hosted_send_custom_data(KODE_MSG_RSP, m, sizeof(h) + (size_t)len);
    free(m);
}

/** @brief INFO, the one op this file answers itself. */
static uint8_t self_info(uint8_t *out, uint16_t *out_len)
{
    kode_info_t i;

    (void)memset(&i, 0, sizeof(i));
    i.wire_version = KODE_WIRE_VERSION;
    i.vault_count  = s_vault;
    i.btkeys_count = s_btkeys;
    i.id_flags     = s_id_flags;
    i.heap_free    = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    i.heap_low     = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    i.heap_largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    i.swaps        = s_swaps;
    i.misses       = s_misses;
    (void)memcpy(out, &i, sizeof(i));
    *out_len = (uint16_t)sizeof(i);
    return KODE_ST_OK;
}

/**
 * @brief The host spoke to this image: it runs, so it stays.
 *
 * A request over peer data has crossed the whole transport and reached this
 * task, which is what an update must prove before it is kept. On a
 * bootloader built with rollback the image is confirmed here, once; on one
 * built without, the call answers that there is nothing to confirm.
 */
static void confirm_once(bool valid)
{
    if ( ksf_should_confirm(&s_confirm, valid) )
    {
        esp_err_t const err = esp_ota_mark_app_valid_cancel_rollback();
        ESP_LOGI(TAG, "the host linked; this image is kept (%s)", esp_err_to_name(err));
    }
}

/** @brief One request: check its frame, run its handler, answer. */
static void serve(const uint8_t *msg, size_t len)
{
    kode_hdr_t h;
    ksf_verdict_t const verdict = ksf_check(msg, len, &h);

    if ( KSF_TOO_SHORT == verdict )
    {
        ESP_LOGW(TAG, "a %u-byte request is shorter than its header", (unsigned)len);
        return;
    }
    if ( KSF_BAD_VERSION == verdict )
    {
        /* Answered anyway, with this side's version in the header: the host
         * then logs both numbers instead of a timeout. */
        ESP_LOGW(TAG, "the host speaks KODE wire v%u, this build v%u",
                 (unsigned)h.version, (unsigned)KODE_WIRE_VERSION);
        answer(&h, KODE_ST_BAD_REQUEST, NULL, 0U);
        return;
    }
    if ( KSF_BAD_LENGTH == verdict )
    {
        answer(&h, KODE_ST_BAD_REQUEST, NULL, 0U);
        return;
    }
    /* Only a request this image can read proves the host speaks to it: one
     * of another wire version would keep an image the host cannot use. */
    confirm_once(KSF_OK == verdict);

    uint8_t *const out = heap_caps_malloc(KODE_MAX_PAYLOAD, MALLOC_CAP_INTERNAL);
    uint16_t out_len = 0U;
    uint8_t  status  = KODE_ST_BAD_REQUEST;
    bool     parking = false;

    if ( NULL == out )
    {
        answer(&h, KODE_ST_REFUSED, NULL, 0U);
        return;
    }
    if ( (KODE_SVC_SELF == h.service) && (KODE_SELF_INFO == h.op) )
    {
        status = self_info(out, &out_len);
    }
    else if ( (KODE_SVC_SELF == h.service) && (KODE_SELF_PARK == h.op) )
    {
        status  = kode_park_request();
        parking = (KODE_ST_OK == status);
    }
    else if ( (KODE_SVC_COUNT > h.service) && (NULL != s_handler[h.service]) )
    {
        status = s_handler[h.service](h.op, &msg[sizeof(h)], h.len, out, &out_len);
    }
    else
    {
        status = KODE_ST_BAD_REQUEST;
    }
    answer(&h, status, out, out_len);
    free(out);
    if ( parking )
    {
        /* After the answer: it is the last frame the host gets. */
        kode_park_now();
    }
}

static void svc_task(void *arg)
{
    svc_job_t job;

    (void)arg;
    for ( ;; )
    {
        if ( xQueueReceive(s_queue, &job, portMAX_DELAY) != pdTRUE )
        {
            continue;
        }
        serve(job.msg, job.len);
        free(job.msg);
    }
}

/**
 * @brief A request arrived. esp-hosted's receive thread: copy it and leave;
 *        when the queue is full, say so at once rather than leave the host
 *        to time out.
 */
static void on_request(uint32_t msg_id, const uint8_t *data, size_t len, void *ctx)
{
    svc_job_t job = { .msg = NULL, .len = len };

    (void)msg_id;
    (void)ctx;
    if ( !ksf_request_fits(data, len) )
    {
        return;
    }
    job.msg = malloc(len);
    if ( NULL == job.msg )
    {
        answer((const kode_hdr_t *)data, KODE_ST_REFUSED, NULL, 0U);
        return;
    }
    (void)memcpy(job.msg, data, len);
    if ( xQueueSend(s_queue, &job, 0) != pdTRUE )
    {
        answer((const kode_hdr_t *)data, KODE_ST_REFUSED, NULL, 0U);
        free(job.msg);
    }
}

esp_err_t kode_svc_init(void)
{
    if ( NULL != s_queue )
    {
        return ESP_OK;
    }
    s_queue = xQueueCreate(SVC_QUEUE_DEPTH, sizeof(svc_job_t));
    if ( NULL == s_queue )
    {
        return ESP_ERR_NO_MEM;
    }
    if ( xTaskCreate(svc_task, "kode_svc", SVC_TASK_STACK, NULL, SVC_TASK_PRIO, NULL) != pdPASS )
    {
        vQueueDelete(s_queue);
        s_queue = NULL;
        return ESP_ERR_NO_MEM;
    }
    return esp_hosted_register_custom_callback(KODE_MSG_REQ, on_request, NULL);
}
