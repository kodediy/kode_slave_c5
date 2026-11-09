/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_id_serial.h
 * @brief The unit's serial from its MAC, the C5's copy of the P4's
 *        khal_identity_encode(): the two must never drift. Plain data, so it
 *        runs on the host (test/test_id_serial.c).
 */#ifndef KODE_ID_SERIAL_H_
#define KODE_ID_SERIAL_H_

#include <stdint.h>

/** @brief Bytes of a MAC address. */
#define KID_MAC_LEN     6U
/** @brief Bytes of a serial, with its NUL: "KODE" + 10 symbols + 1 check. */
#define KID_SERIAL_LEN  16U

/**
 * @brief Encode a MAC as the unit's serial.
 * @param mac The six MAC bytes, most significant first.
 * @param out Receives the serial and its NUL (KID_SERIAL_LEN bytes).
 */
void kid_serial_of(const uint8_t mac[KID_MAC_LEN], char out[KID_SERIAL_LEN]);

#endif /* KODE_ID_SERIAL_H_ */
