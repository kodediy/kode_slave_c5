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
        out->len = len;
        if ( len > hdr )
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
