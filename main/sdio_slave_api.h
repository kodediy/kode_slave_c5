/*
 * SPDX-FileCopyrightText: 2015-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SDIO_SLAVE_API_H
#define __SDIO_SLAVE_API_H

#if CONFIG_SOC_SDIO_SLAVE_SUPPORTED

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/**
 * @brief KODE: reset the SDIO slave so it counts packets and tokens from zero,
 *        whatever state the data path is in.
 *
 * Stops the slave, resets it, enables the host interrupts and starts it: the
 * else-branch of the reset in the transport's operations, which does nothing
 * once the data path is closed. Does not touch the interface state.
 *
 * @return ESP_OK, or the error of the reset or the start.
 */
esp_err_t sdio_park(void);

/**
 * @brief KODE: wait until every buffer handed to the SDIO driver has been read
 *        by the host.
 *
 * @param timeout_ms The longest wait, in milliseconds.
 * @return true when nothing is queued for the host, false on the timeout.
 */
bool sdio_tx_drained(uint32_t timeout_ms);

#else
    #error "SDIO is not supported for this target. Please use SPI"
#endif

#endif
