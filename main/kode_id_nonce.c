/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_id_nonce.c
 * @brief The signed message's shape: plain data, no hardware.
 */
#include <string.h>

#include "kode_id_nonce.h"

size_t kid_auth_message(const char *nonce, size_t len, uint8_t *out, size_t cap)
{
    size_t const pre = sizeof(KID_AUTH_PREFIX) - 1U;
    size_t n = 0U;

    if ( (NULL != nonce) && (NULL != out) && ((pre + len) <= cap) )
    {
        (void)memcpy(out, KID_AUTH_PREFIX, pre);
        (void)memcpy(&out[pre], nonce, len);
        n = pre + len;
    }
    return n;
}
