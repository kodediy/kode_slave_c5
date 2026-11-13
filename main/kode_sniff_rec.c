/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_sniff_rec.c
 * @brief One Wi-Fi frame heard, as the record the wire carries: plain data,
 *        no hardware.
 */
#include <string.h>

#include "kode_sniff_rec.h"

/** @brief Whether the frame is a data frame. */
static bool is_data(const uint8_t fc[KSR_FC_LEN])
{
    return KSR_DATA == ksr_kind(fc);
}

/** @brief Whether a frame of this kind carries a third address: management and data do. */
static bool has_addr3(const uint8_t fc[KSR_FC_LEN])
{
    ksr_kind_t const kind = ksr_kind(fc);

    return (KSR_MGMT == kind) || (KSR_DATA == kind);
}

ksr_kind_t ksr_kind(const uint8_t fc[KSR_FC_LEN])
{
    return (ksr_kind_t)((fc[0] >> KSR_TYPE_SHIFT) & KSR_TYPE_MASK);
}

uint8_t ksr_header_len(const uint8_t fc[KSR_FC_LEN])
{
    uint8_t n = KSR_HDR_LEN;

    if ( is_data(fc) )
    {
        if ( 0U != (fc[0] & KSR_QOS_BIT) )
        {
            n = (uint8_t)(n + KSR_QOS_LEN);
        }
        if ( (0U != (fc[1] & KSR_TODS_BIT)) && (0U != (fc[1] & KSR_FROMDS_BIT)) )
        {
            n = (uint8_t)(n + KSR_ADDR4_LEN);
        }
    }
    return n;
}

bool ksr_build(const uint8_t *frame, uint16_t len, int8_t rssi, kode_sniff_rec_t *out)
{
    bool built = false;

    if ( (NULL != frame) && (NULL != out) && (KSR_MIN_LEN <= len) )
    {
        uint16_t const hdr = ksr_header_len(frame);

        (void)memset(out, 0, sizeof(*out));
        out->rssi = rssi;
        (void)memcpy(out->fc, frame, KSR_FC_LEN);
        (void)memcpy(out->addr1, &frame[KSR_ADDR1_AT], KSR_ADDR_LEN);
        if ( KSR_ADDR2_MIN_LEN <= len )
        {
            (void)memcpy(out->addr2, &frame[KSR_ADDR2_AT], KSR_ADDR_LEN);
        }
        if ( (KSR_HDR_LEN <= len) && has_addr3(frame) )
        {
            (void)memcpy(out->addr3, &frame[KSR_ADDR3_AT], KSR_ADDR_LEN);
        }
        out->len = len;
        /* What follows a data frame's header is a third party's traffic:
         * none of it is kept. */
        if ( (len > hdr) && !is_data(frame) )
        {
            uint16_t n = (uint16_t)(len - hdr);

            if ( KODE_SNIFF_HEAD_LEN < n )
            {
                n = KODE_SNIFF_HEAD_LEN;
            }
            (void)memcpy(out->head, &frame[hdr], n);
        }
        built = true;
    }
    return built;
}

size_t ksr_pack(const kode_sniff_rec_t *rec, bool wide, uint8_t *out)
{
    size_t n = sizeof(*rec);

    if ( wide )
    {
        (void)memcpy(out, rec, sizeof(*rec));
    }
    else
    {
        kode_sniff_rec_short_t s;

        (void)memset(&s, 0, sizeof(s));
        s.rssi = rec->rssi;
        (void)memcpy(s.fc, rec->fc, sizeof(s.fc));
        (void)memcpy(s.addr1, rec->addr1, sizeof(s.addr1));
        (void)memcpy(s.addr2, rec->addr2, sizeof(s.addr2));
        s.len = rec->len;
        (void)memcpy(s.head, rec->head, sizeof(s.head));
        (void)memcpy(out, &s, sizeof(s));
        n = sizeof(s);
    }
    return n;
}
