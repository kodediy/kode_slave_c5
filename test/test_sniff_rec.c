/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_sniff_rec.c
 * @brief The Wi-Fi frames record on the host: the kind of a frame, the length
 *        of its MAC header, and the record built from a frame as the radio
 *        hands it over - beacons with their network's name, the third
 *        address, QoS data, four addresses, control frames with no second
 *        address, short frames and runts - and the record written at the
 *        size each P4 asks for.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_sniff_rec.h"

/** @brief Longest frame these tests build. */
#define T_FRAME_MAX  128U

/** @brief Where address 3 starts in a frame. */
#define T_ADDR3_AT   16U

/** @brief A beacon's fixed bytes: timestamp, interval and capabilities. */
#define T_BEACON_FIXED  12U

/** @brief The longest network name. */
#define T_SSID_MAX      32U

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

    /* A beacon: management, 24-byte header, its three addresses, and the
     * whole head after it. */
    {
        uint8_t const fc[2] = { 0x80U, 0x00U };
        make_frame(f, 100U, fc[0], fc[1]);
        assert(KSR_MGMT == ksr_kind(fc));
        assert(24U == ksr_header_len(fc));
        poison(&r);
        assert(ksr_build(f, 100U, -57, &r));
        assert(-57 == r.rssi);
        assert((0x80U == r.fc[0]) && (0x00U == r.fc[1]));
        assert(memcmp(r.addr1, &f[4], 6U) == 0);
        assert(memcmp(r.addr2, &f[10], 6U) == 0);
        assert(memcmp(r.addr3, &f[T_ADDR3_AT], 6U) == 0);
        assert(100U == r.len);
        assert(memcmp(r.head, &f[24], KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* The head is what a beacon's reader needs: the 12 fixed bytes, with the
     * capabilities and their privacy bit, and the name's element whole when
     * the name is as long as a name can be. */
    {
        uint8_t const hdr = 24U;
        assert(KODE_SNIFF_HEAD_LEN >= (T_BEACON_FIXED + 2U + T_SSID_MAX));
        make_frame(f, 110U, 0x80U, 0x00U);
        f[hdr + 10U] = 0x11U;                              /* capabilities: ESS and privacy */
        f[hdr + T_BEACON_FIXED]      = 0U;                 /* the name's element */
        f[hdr + T_BEACON_FIXED + 1U] = (uint8_t)T_SSID_MAX;
        (void)memset(&f[hdr + T_BEACON_FIXED + 2U], 'n', T_SSID_MAX);
        assert(ksr_build(f, 110U, -40, &r));
        assert(0x11U == r.head[10]);
        assert(0U == r.head[T_BEACON_FIXED]);
        assert(T_SSID_MAX == r.head[T_BEACON_FIXED + 1U]);
        for ( uint8_t i = 0U; i < T_SSID_MAX; i++ )
        {
            assert('n' == r.head[T_BEACON_FIXED + 2U + i]);
        }
    }

    /* A deauthentication a station sends carries the network's address
     * third: a management frame of 26 bytes, with two bytes of reason. */
    {
        uint8_t const fc[2] = { 0xC0U, 0x00U };
        make_frame(f, 26U, fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, 26U, -61, &r));
        assert(memcmp(r.addr3, &f[T_ADDR3_AT], 6U) == 0);
        assert(memcmp(r.head, &f[24], 2U) == 0);
        assert(memcmp(&r.head[2], zero, KODE_SNIFF_HEAD_LEN - 2U) == 0);
    }

    /* Address 3 belongs to a management or a data frame with its whole
     * header. A control frame has none, however long it is, and neither has
     * a frame cut short of the header. */
    {
        uint8_t const bar[2] = { 0x84U, 0x00U };           /* a block ack request */
        make_frame(f, 24U, bar[0], bar[1]);
        assert(KSR_CTRL == ksr_kind(bar));
        poison(&r);
        assert(ksr_build(f, 24U, -50, &r));
        assert(memcmp(r.addr3, zero, 6U) == 0);

        make_frame(f, 23U, 0x80U, 0x00U);
        poison(&r);
        assert(ksr_build(f, 23U, -50, &r));
        assert(memcmp(r.addr3, zero, 6U) == 0);

        make_frame(f, 24U, 0x08U, 0x01U);
        poison(&r);
        assert(ksr_build(f, 24U, -50, &r));
        assert(memcmp(r.addr3, &f[T_ADDR3_AT], 6U) == 0);
    }

    /* A protected QoS data frame: 26-byte header, flags copied unchanged,
     * and nothing past the header - that is a third party's traffic. */
    {
        uint8_t const fc[2] = { 0x88U, 0x41U };
        make_frame(f, 100U, fc[0], fc[1]);
        assert(KSR_DATA == ksr_kind(fc));
        assert(26U == ksr_header_len(fc));
        poison(&r);
        assert(ksr_build(f, 100U, -70, &r));
        assert((0x88U == r.fc[0]) && (0x41U == r.fc[1]));
        assert(100U == r.len);
        assert(memcmp(r.head, zero, KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* Four addresses: 32 bytes with QoS, 30 without. */
    {
        uint8_t const qos[2] = { 0x88U, 0x03U };
        uint8_t const plain[2] = { 0x08U, 0x03U };
        assert(32U == ksr_header_len(qos));
        assert(30U == ksr_header_len(plain));
        make_frame(f, 100U, plain[0], plain[1]);
        poison(&r);
        assert(ksr_build(f, 100U, -60, &r));
        assert(memcmp(r.head, zero, KODE_SNIFF_HEAD_LEN) == 0);
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

    /* A frame that ends inside what would be the head: the rest is zeros. */
    {
        uint8_t const fc[2] = { 0x80U, 0x00U };
        make_frame(f, 28U, fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, 28U, -66, &r));
        assert(memcmp(r.head, &f[24], 4U) == 0);
        assert(memcmp(&r.head[4], zero, KODE_SNIFF_HEAD_LEN - 4U) == 0);
    }

    /* A frame that ends exactly at the MAC header has an empty head. */
    {
        make_frame(f, 24U, 0x08U, 0x01U);
        poison(&r);
        assert(ksr_build(f, 24U, -66, &r));
        assert(memcmp(r.head, zero, KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* Address 2 is there from 16 bytes and not at 15. */
    {
        uint8_t const fc[2] = { 0x80U, 0x00U };
        make_frame(f, 16U, fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, 16U, -50, &r));
        assert(memcmp(r.addr2, &f[10], 6U) == 0);
        make_frame(f, 15U, fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, 15U, -50, &r));
        assert(memcmp(r.addr2, zero, 6U) == 0);
    }

    /* The head is full when the frame ends a whole head past its header, and
     * one byte short of that it keeps all but the last, which is a zero. */
    {
        uint8_t const fc[2] = { 0x80U, 0x00U };
        uint8_t const hdr = ksr_header_len(fc);
        make_frame(f, (uint16_t)(hdr + KODE_SNIFF_HEAD_LEN), fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, (uint16_t)(hdr + KODE_SNIFF_HEAD_LEN), -50, &r));
        assert(memcmp(r.head, &f[hdr], KODE_SNIFF_HEAD_LEN) == 0);
        make_frame(f, (uint16_t)(hdr + KODE_SNIFF_HEAD_LEN - 1U), fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, (uint16_t)(hdr + KODE_SNIFF_HEAD_LEN - 1U), -50, &r));
        assert(memcmp(r.head, &f[hdr], KODE_SNIFF_HEAD_LEN - 1U) == 0);
        assert(0U == r.head[KODE_SNIFF_HEAD_LEN - 1U]);
    }

    /* Four addresses and QoS together: a 32-byte header, and no head. */
    {
        uint8_t const fc[2] = { 0x88U, 0x03U };
        assert(32U == ksr_header_len(fc));
        make_frame(f, 100U, fc[0], fc[1]);
        poison(&r);
        assert(ksr_build(f, 100U, -50, &r));
        assert(memcmp(r.head, zero, KODE_SNIFF_HEAD_LEN) == 0);
    }

    /* Only a data frame has a longer header: management and control stay at
     * 24 with ToDS and FromDS set, or with bit 7 of byte 0 set. */
    {
        uint8_t const mgmt[2]  = { 0x80U, 0x03U };
        uint8_t const mgmt2[2] = { 0xB0U, 0x03U };
        uint8_t const ctrl[2]  = { 0xD4U, 0x03U };
        uint8_t const ctrl2[2] = { 0xB4U, 0x00U };
        assert(24U == ksr_header_len(mgmt));
        assert(24U == ksr_header_len(mgmt2));
        assert(24U == ksr_header_len(ctrl));
        assert(24U == ksr_header_len(ctrl2));
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

    /* This C5 with a P4 that asks with KODE_SNIFF_WIDE: the record whole. */
    {
        uint8_t out[sizeof(kode_sniff_rec_t)];

        make_frame(f, 100U, 0x80U, 0x00U);
        assert(ksr_build(f, 100U, -57, &r));
        (void)memset(out, 0xEE, sizeof(out));
        assert(sizeof(kode_sniff_rec_t) == ksr_pack(&r, true, out));
        assert(memcmp(out, &r, sizeof(r)) == 0);
    }

    /* This C5 with a P4 from before the flag, which asks with 0: the 25-byte
     * record that P4 reads, written out here as it was, with nothing past it. */
    {
        typedef struct __attribute__((packed)) {
            int8_t   rssi;
            uint8_t  fc[2];
            uint8_t  addr1[6];
            uint8_t  addr2[6];
            uint16_t len;
            uint8_t  head[8];
        } old_rec_t;
        _Static_assert(sizeof(old_rec_t) == 25U, "the record a P4 from before the flag reads");
        uint8_t   out[sizeof(kode_sniff_rec_t)];
        old_rec_t o;

        make_frame(f, 100U, 0x80U, 0x00U);
        assert(ksr_build(f, 100U, -57, &r));
        (void)memset(out, 0xEE, sizeof(out));
        assert(sizeof(old_rec_t) == ksr_pack(&r, false, out));
        (void)memcpy(&o, out, sizeof(o));
        assert(-57 == o.rssi);
        assert((0x80U == o.fc[0]) && (0x00U == o.fc[1]));
        assert(memcmp(o.addr1, &f[4], 6U) == 0);
        assert(memcmp(o.addr2, &f[10], 6U) == 0);
        assert(100U == o.len);
        assert(memcmp(o.head, &f[24], sizeof(o.head)) == 0);
        assert(0xEEU == out[sizeof(old_rec_t)]);
    }

    puts("sniff rec: ok");
    return 0;
}
