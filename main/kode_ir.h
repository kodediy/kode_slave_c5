/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_ir.h
 * @brief The Kode Dot's infrared block, served to the host over peer data.
 */
#ifndef KODE_IR_H_
#define KODE_IR_H_

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start the infrared service: its task, its queue and its one
 *        peer-data handler.
 *
 * Touches no pin. The RMT channels on IO24 and IO23 are opened by the first
 * request from the host, so an image that never receives one leaves both
 * pins as they reset.
 *
 * @return ESP_OK, ESP_ERR_NO_MEM, or what registering the handler returned.
 */
esp_err_t kode_ir_init(void);

/**
 * @brief Close the RMT channels if they are open, so IO24 and IO23 are
 *        released as at reset. KODE: used when the C5 parks.
 *
 * Queues the close behind whatever the task is doing, so it never races a
 * transmission and returns at once. The next request from a host opens the
 * block again.
 */
void kode_ir_park(void);

#ifdef __cplusplus
}
#endif

#endif /* KODE_IR_H_ */
