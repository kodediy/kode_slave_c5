/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_id_serial.c
 * @brief The unit's serial on the C5 against the vectors the P4 pins for
 *        khal_identity_encode(): the two encoders must agree, because the
 *        serial is the unit's name in the cloud.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_id_serial.h"

/** @brief One MAC and the serial it must encode to. */
typedef struct {
    uint8_t     mac[KID_MAC_LEN];   /**< The six MAC bytes.        */
    const char *want;               /**< The serial, NUL-ended.    */
} serial_vec_t;

int main(void)
{
    static const serial_vec_t VECS[] = {
        { { 0xE8U, 0xF6U, 0x0AU, 0xE7U, 0x6CU, 0x1DU }, "KODE78YR5EEV0XS" },
        { { 0xE8U, 0xF6U, 0x0AU, 0xE7U, 0x6CU, 0x1EU }, "KODE78YR5EEV0YQ" },
        { { 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U }, "KODE0000000001Y" },
        { { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU }, "KODE7ZZZZZZZZZ2" },
    };
    char out[KID_SERIAL_LEN];

    for ( size_t i = 0U; (sizeof(VECS) / sizeof(VECS[0])) > i; i++ )
    {
        (void)memset(out, 'x', sizeof(out));
        kid_serial_of(VECS[i].mac, out);
        assert(strcmp(out, VECS[i].want) == 0);
        assert(strlen(out) == (KID_SERIAL_LEN - 1U));
    }

    puts("id serial: ok");
    return 0;
}
