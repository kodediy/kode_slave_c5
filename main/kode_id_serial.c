/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_id_serial.c
 * @brief The unit's serial from its MAC: plain data, no hardware.
 */
#include <string.h>

#include "kode_id_serial.h"

/** @brief Bytes of the "KODE" prefix. */
#define SERIAL_PREFIX_LEN   4U
/** @brief Crockford symbols that carry the MAC. */
#define SERIAL_SYMBOLS      10U
/** @brief Bits one symbol carries. */
#define SERIAL_SYMBOL_BITS  5U
/** @brief Mask of one symbol. */
#define SERIAL_SYMBOL_MASK  0x1FU
/** @brief The alphabet's size, and the Luhn modulus. */
#define SERIAL_RADIX        32U
/** @brief Shift that brings the first symbol down: 9 symbols of 5 bits. */
#define SERIAL_FIRST_SHIFT  45U
/** @brief Bits in a byte, for folding the MAC into one number. */
#define SERIAL_BYTE_BITS    8U
/** @brief The Luhn factor of the rightmost symbol. */
#define SERIAL_FACTOR_FIRST 2U
/** @brief The Luhn factor's two values sum to this (2 and 1 alternate). */
#define SERIAL_FACTOR_SUM   3U
/** @brief Where the check symbol sits in the serial. */
#define SERIAL_CHECK_AT     (SERIAL_PREFIX_LEN + SERIAL_SYMBOLS)

_Static_assert(KID_SERIAL_LEN == (SERIAL_CHECK_AT + 2U), "prefix + symbols + check + NUL");

/** @brief Crockford base 32: no I, L, O or U. */
static const char ID_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

void kid_serial_of(const uint8_t mac[KID_MAC_LEN], char out[KID_SERIAL_LEN])
{
    uint64_t value  = 0U;
    uint32_t sum    = 0U;
    uint32_t factor = SERIAL_FACTOR_FIRST;
    uint8_t  sym[SERIAL_SYMBOLS];

    for ( uint8_t i = 0U; KID_MAC_LEN > i; i++ )
    {
        value = (value << SERIAL_BYTE_BITS) | (uint64_t)mac[i];
    }
    (void)memcpy(out, "KODE", SERIAL_PREFIX_LEN);
    for ( uint8_t i = 0U; SERIAL_SYMBOLS > i; i++ )
    {
        uint8_t const shift = (uint8_t)(SERIAL_FIRST_SHIFT - ((uint32_t)i * SERIAL_SYMBOL_BITS));
        sym[i] = (uint8_t)((value >> shift) & SERIAL_SYMBOL_MASK);
        out[SERIAL_PREFIX_LEN + i] = ID_ALPHABET[sym[i]];
    }
    /* Luhn mod 32, rightmost symbol first, the factor alternating 2, 1. */
    for ( uint8_t k = SERIAL_SYMBOLS; 0U < k; k-- )
    {
        uint32_t const p = factor * (uint32_t)sym[k - 1U];

        sum += (p / SERIAL_RADIX) + (p % SERIAL_RADIX);
        factor = SERIAL_FACTOR_SUM - factor;
    }
    out[SERIAL_CHECK_AT] = ID_ALPHABET[(SERIAL_RADIX - (sum % SERIAL_RADIX)) % SERIAL_RADIX];
    out[SERIAL_CHECK_AT + 1U] = '\0';
}
