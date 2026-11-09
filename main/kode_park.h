/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_park.h
 * @brief The C5 parks: it keeps its Wi-Fi station associated, drops the host
 *        and waits for the next one (KODE_SELF_PARK, kode_wire.h).
 */
#ifndef KODE_PARK_H_
#define KODE_PARK_H_

#include <stdbool.h>
#include <stdint.h>

/** @brief The longest wait, in milliseconds, for the park answer to leave over SDIO. */
#define KODE_PARK_TX_MS      50U

/** @brief The C5 pin that switches the J3 expansion supply; the P4 drives it over RPC. */
#define KODE_PARK_PIN_J3     5U

/**
 * @brief Answer a park request: is there a station worth keeping?
 *
 * Reads the station state. With a station associated it arms the park, which
 * kode_park_now() carries out once the answer is sent.
 *
 * @return KODE_ST_OK when the park is armed, KODE_ST_REFUSED when no station
 *         is associated (nothing changes).
 */
uint8_t kode_park_request(void);

/**
 * @brief Park, if a request armed it. Called by the KODE task right after the
 *        answer is queued, and never from anywhere else.
 *
 * Stops station frames for the host, closes the data path (host-bound
 * packets are dropped from then on), waits for the answer to leave and resets
 * the SDIO slave; the C5 counts as parked only if that reset worked. Then it closes
 * the infrared block, releases the expansion supply pin and switches
 * Bluetooth off, if the host had started it. The station stays associated.
 */
void kode_park_now(void);

/**
 * @brief Is the C5 parked, waiting for a host?
 * @return true from kode_park_now() until kode_park_resume().
 */
bool kode_park_is_parked(void);

/**
 * @brief A host is back (the data path opened): leave the parked state.
 *
 * Only the flag and the log: the station's receive callback is given back by
 * host_reset_task, parked or not. Task context only (it logs): the data
 * path's opening is signalled from the SDIO ISR and this runs after it, in
 * that task. The Bluetooth controller stays off; the host's bring-up starts it.
 */
void kode_park_resume(void);

#endif /* KODE_PARK_H_ */
