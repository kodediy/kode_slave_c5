/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_svc_frame.c
 * @brief The request frame check and the confirm-once policy: plain data,
 *        no hardware.
 */
#include <string.h>

#include "kode_svc_frame.h"

ksf_verdict_t ksf_check(const uint8_t *msg, size_t len, kode_hdr_t *h)
{
    ksf_verdict_t verdict = KSF_OK;

    if ( sizeof(*h) > len )
    {
        verdict = KSF_TOO_SHORT;
    }
    else
    {
        (void)memcpy(h, msg, sizeof(*h));
        if ( KODE_WIRE_VERSION != h->version )
        {
            verdict = KSF_BAD_VERSION;
        }
        else if ( ((size_t)h->len + sizeof(*h)) != len )
        {
            verdict = KSF_BAD_LENGTH;
        }
        else
        {
            /* readable */
        }
    }
    return verdict;
}

bool ksf_request_fits(const void *data, size_t len)
{
    return (NULL != data) && (sizeof(kode_hdr_t) <= len)
           && ((sizeof(kode_hdr_t) + (size_t)KODE_MAX_PAYLOAD) >= len);
}

bool ksf_should_confirm(ksf_confirm_t *st, bool valid)
{
    bool fire = false;

    if ( valid && (!st->done) )
    {
        st->done = true;
        fire = true;
    }
    return fire;
}
