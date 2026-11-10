/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_sniff_rec.c
 * @brief The Wi-Fi frames record on the host: the kind of a frame, the length
 *        of its MAC header, and the record built from a frame as the radio
 *        hands it over - beacons, QoS data, four addresses, control frames
 *        with no second address, short frames and runts.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_sniff_rec.h"

/** @brief Longest frame these tests build. */
#define T_FRAME_MAX  64U

/** @brief A frame of @p len bytes whose byte i is i + 1, with @p fc0, @p fc1 on top. */
static void make_frame(uint8_t *f, uint16_t len, uint8_t fc0, uint8_t fc1)
{
    for ( uint16_t i = 0U; i < len; i++ )
    {
        f[i] = (uint8_t)(i + 1U);
    }
    f[0] = fc0;
    f[1] = fc1;
}

/** @brief A record filled with a pattern, to see what a build leaves alone. */
static void poison(kode_sniff_rec_t *r)
{
    (void)memset(r, 0xA5, sizeof(*r));
}

int main(void)
{
    uint8_t f[T_FRAME_MAX];
    kode_sniff_rec_t r;
    kode_sniff_rec_t untouched;
    uint8_t const zero[KODE_SNIFF_HEAD_LEN] = { 0U };

    /* A beacon: management, 24-byte header, both addresses, 8 bytes after. */
    {
        uint8_t const fc[2] = { 0x80U, 0x00U };
        make_frame(f, 40U, fc[0], fc[1]);
        assert(KSR_MGMT == ksr_kind(fc));
        assert(24U == ksr_header_len(fc));
        poison(&r);
        assert(ksr_build(f, 40U, -57, &r));
        assert(-57 == r.rssi);
        assert((0x80U == r.fc[0]) && (0x00U == r.fc[1]));
        assert(memcmp(r.addr1, &f[4], 6U) == 0);
        assert(memcmp(r.addr2, &f[10], 6U) == 0);
        assert(40U == r.len);
        assert(memcmp(r.head, &f[24], KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* A protected QoS data frame: 26-byte header, flags copied unchanged. */
    {
        uint8_t const fc[2] = { 0x88U, 0x41U };
        make_frame(f, 60U, fc[0], fc[1]);
        assert(KSR_DATA == ksr_kind(fc));
        assert(26U == ksr_header_len(fc));
        assert(ksr_build(f, 60U, -70, &r));
        assert((0x88U == r.fc[0]) && (0x41U == r.fc[1]));
        assert(60U == r.len);
        assert(memcmp(r.head, &f[26], KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* Four addresses: 32 bytes with QoS, 30 without. */
    {
        uint8_t const qos[2] = { 0x88U, 0x03U };
        uint8_t const plain[2] = { 0x08U, 0x03U };
        assert(32U == ksr_header_len(qos));
        assert(30U == ksr_header_len(plain));
        make_frame(f, 50U, plain[0], plain[1]);
        assert(ksr_build(f, 50U, -60, &r));
        assert(memcmp(r.head, &f[30], KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* An acknowledgement: control, 10 bytes, no second address, no head. */
    {
        uint8_t const fc[2] = { 0xD4U, 0x00U };
        make_frame(f, 10U, fc[0], fc[1]);
        assert(KSR_CTRL == ksr_kind(fc));
        poison(&r);
        assert(ksr_build(f, 10U, -44, &r));
        assert(memcmp(r.addr1, &f[4], 6U) == 0);
        assert(memcmp(r.addr2, zero, 6U) == 0);
        assert(memcmp(r.head, zero, KODE_SNIFF_HEAD_LEN) == 0);
        assert(10U == r.len);
    }

    /* A data frame that ends inside what would be the head: the rest is zeros. */
    {
        uint8_t const fc[2] = { 0x08U, 0x01U };
        make_frame(f, 28U, fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, 28U, -66, &r));
        assert(memcmp(r.head, &f[24], 4U) == 0);
        assert(memcmp(&r.head[4], zero, 4U) == 0);
    }

    /* A frame that ends exactly at the MAC header has an empty head. */
    {
        make_frame(f, 24U, 0x08U, 0x01U);
        poison(&r);
        assert(ksr_build(f, 24U, -66, &r));
        assert(memcmp(r.head, zero, KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* The type bits: the fourth value is reserved. */
    {
        uint8_t const fc[2] = { 0x0CU, 0x00U };
        assert(KSR_OTHER == ksr_kind(fc));
    }

    /* A runt is refused and the record is left as it was. */
    {
        make_frame(f, 9U, 0x80U, 0x00U);
        poison(&r);
        poison(&untouched);
        assert(!ksr_build(f, 9U, -50, &r));
        assert(memcmp(&r, &untouched, sizeof(r)) == 0);
        assert(!ksr_build(NULL, 40U, -50, &r));
        assert(!ksr_build(f, 40U, -50, NULL));
    }

    puts("sniff rec: ok");
    return 0;
}
