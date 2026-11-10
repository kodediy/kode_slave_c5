/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_svc.h
 * @brief The KODE services on the C5: one peer-data id, one task, a handler
 *        per service (kode_wire.h).
 */
#ifndef KODE_SVC_H_
#define KODE_SVC_H_

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/**
 * @brief A service's handler. Runs on the kode_svc task, one request at a
 *        time.
 *
 * @param op      The request's op.
 * @param req     Its payload.
 * @param len     Payload bytes.
 * @param out     The answer's payload buffer, KODE_MAX_PAYLOAD bytes.
 * @param out_len Out: answer bytes; 0 when the answer has no payload.
 * @return The answer's KODE_ST_* status.
 */
typedef uint8_t (*kode_svc_handler_t)(uint8_t op, const uint8_t *req, uint16_t len,
                                      uint8_t *out, uint16_t *out_len);

/**
 * @brief Register a service's handler. Before kode_svc_init().
 * @param service KODE_SVC_VAULT, _ID, _BTKEYS or _SNIFF.
 * @param h       The handler.
 */
void kode_svc_register(uint8_t service, kode_svc_handler_t h);

/**
 * @brief What one service reports through INFO.
 * @param service KODE_SVC_VAULT (networks saved), _BTKEYS (keys held) or
 *                _ID (KODE_ID_F_* flags).
 * @param value   The number, or the flags.
 */
void kode_svc_set_count(uint8_t service, uint8_t value);

/**
 * @brief Count one token seen on the HCI path.
 * @param known True when it was swapped, false when nobody knew it.
 */
void kode_svc_add_swap(bool known);

/**
 * @brief The queue, the task and the peer-data handler. Opens nothing else.
 * @return ESP_OK, or the error of whatever could not be created.
 */
esp_err_t kode_svc_init(void);

#endif /* KODE_SVC_H_ */
