/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_svc_frame.c
 * @brief The service dispatcher's frame check and its confirm-once policy:
 *        what a request must look like before any handler sees it, and that
 *        only the first well-formed request keeps an updated image.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_svc_frame.h"
#include "../main/kode_wire.h"

/** @brief A header for a request, ready to be copied into a frame. */
static kode_hdr_t header(uint8_t version, uint16_t payload)
{
    kode_hdr_t h;

    (void)memset(&h, 0, sizeof(h));
    h.version = version;
    h.service = KODE_SVC_VAULT;
    h.op      = KODE_VAULT_LIST;
    h.seq     = 7U;
    h.len     = payload;
    return h;
}

/** @brief Check a frame made of @p h and @p total bytes in all. */
static ksf_verdict_t check(const kode_hdr_t *h, size_t total, kode_hdr_t *got)
{
    static uint8_t frame[sizeof(kode_hdr_t) + KODE_MAX_PAYLOAD + 1U];

    (void)memset(frame, 0, sizeof(frame));
    (void)memcpy(frame, h, sizeof(*h));
    return ksf_check(frame, total, got);
}

int main(void)
{
    kode_hdr_t got;
    kode_hdr_t const good = header(KODE_WIRE_VERSION, 4U);
    size_t const hdr = sizeof(kode_hdr_t);

    /* Shorter than a header: nothing to answer. */
    assert(ksf_check((const uint8_t *)&good, 0U, &got) == KSF_TOO_SHORT);
    assert(ksf_check((const uint8_t *)&good, hdr - 1U, &got) == KSF_TOO_SHORT);

    /* A wrong wire version is told apart from a malformed length, and the
     * header still comes back so the answer can echo it. */
    kode_hdr_t const old = header((uint8_t)(KODE_WIRE_VERSION - 1U), 4U);
    assert(check(&old, hdr + 4U, &got) == KSF_BAD_VERSION);
    assert((KODE_WIRE_VERSION - 1U) == got.version);
    assert(7U == got.seq);
    /* The version is judged before the length. */
    assert(check(&old, hdr + 5U, &got) == KSF_BAD_VERSION);

    /* The length must match the header to the byte. */
    assert(check(&good, hdr + 3U, &got) == KSF_BAD_LENGTH);
    assert(check(&good, hdr + 5U, &got) == KSF_BAD_LENGTH);
    assert(check(&good, hdr, &got) == KSF_BAD_LENGTH);

    /* A good frame, and the header it hands back. */
    (void)memset(&got, 0, sizeof(got));
    assert(check(&good, hdr + 4U, &got) == KSF_OK);
    assert((KODE_SVC_VAULT == got.service) && (KODE_VAULT_LIST == got.op));
    assert((7U == got.seq) && (4U == got.len));

    /* An empty payload is a frame too. */
    kode_hdr_t const empty = header(KODE_WIRE_VERSION, 0U);
    assert(check(&empty, hdr, &got) == KSF_OK);

    /* The largest payload, whole. */
    kode_hdr_t const big = header(KODE_WIRE_VERSION, KODE_MAX_PAYLOAD);
    assert(check(&big, hdr + KODE_MAX_PAYLOAD, &got) == KSF_OK);

    /* What the receive thread lets through to the queue. */
    static uint8_t raw[sizeof(kode_hdr_t) + KODE_MAX_PAYLOAD + 1U];
    assert(ksf_request_fits(raw, hdr));
    assert(ksf_request_fits(raw, hdr + KODE_MAX_PAYLOAD));
    assert(!ksf_request_fits(raw, hdr + KODE_MAX_PAYLOAD + 1U));
    assert(!ksf_request_fits(raw, hdr - 1U));
    assert(!ksf_request_fits(raw, 0U));
    assert(!ksf_request_fits(NULL, hdr));

    /* Confirm once: only a well-formed request counts, and only the first. */
    ksf_confirm_t c = { false };
    assert(!ksf_should_confirm(&c, false));          /* wrong version: no */
    assert(!ksf_should_confirm(&c, false));
    assert(ksf_should_confirm(&c, true));            /* the first good one */
    assert(!ksf_should_confirm(&c, true));           /* never twice */
    assert(!ksf_should_confirm(&c, false));
    c.done = false;                                  /* a new boot starts over */
    assert(ksf_should_confirm(&c, true));

    puts("svc frame: ok");
    return 0;
}
