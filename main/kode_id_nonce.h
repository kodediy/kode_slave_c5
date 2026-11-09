/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_id_nonce.h
 * @brief The one message the unit's key signs: "kode-auth/v1\n" + a nonce
 *        from the cloud's challenge, the prefix always added here. Plain
 *        data, so it runs on the host (test/test_id_nonce.c).
 */#ifndef KODE_ID_NONCE_H_
#define KODE_ID_NONCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @brief What precedes every nonce the key signs. */
#define KID_AUTH_PREFIX      "kode-auth/v1\n"
/**
 * @brief Build the signed message: KID_AUTH_PREFIX then the nonce.
 * @param nonce Checked with kode_nonce_ok() (kode_wire.h) first.
 * @param len   Its length.
 * @param out   Where the message goes.
 * @param cap   Bytes available.
 * @return The message length, or 0 when it does not fit.
 */
size_t kid_auth_message(const char *nonce, size_t len, uint8_t *out, size_t cap);

#endif /* KODE_ID_NONCE_H_ */
