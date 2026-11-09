/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_hci_filter.c
 * @brief The HCI filter: which host-to-controller commands carry a kodeOS
 *        token, and what happens to a token nobody knows.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_hci_filter.h"

static const uint8_t TOK[16] = { 'K', 'B', 'T', 'L', 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0 };
static const uint8_t KEY[16] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

static bool look(const uint8_t t[KODE_TOKEN_LEN], uint8_t k[KODE_BTKEY_LEN])
{
    if ( memcmp(t, TOK, 16) == 0 )
    {
        memcpy(k, KEY, 16);
        return true;
    }
    return false;
}

int main(void)
{
    uint8_t p[22] = { 0x01, 0x1A, 0x20, 18, 0x40, 0x00 };
    memcpy(&p[6], TOK, 16);
    assert(khf_filter(p, sizeof(p), look) == KHF_SWAPPED);
    assert(memcmp(&p[6], KEY, 16) == 0);

    uint8_t real[22] = { 0x01, 0x1A, 0x20, 18, 0x40, 0x00, 9, 9, 9 };   /* a sketch's own key */
    uint8_t copy[22];
    memcpy(copy, real, 22);
    assert(khf_filter(real, sizeof(real), look) == KHF_NONE);
    assert(memcmp(real, copy, 22) == 0);

    uint8_t unk[22] = { 0x01, 0x1A, 0x20, 18, 0x40, 0x00, 'K', 'B', 'T', 'L', 7 };
    assert(khf_filter(unk, sizeof(unk), look) == KHF_UNKNOWN);

    uint8_t shortp[10] = { 0x01, 0x1A, 0x20, 18 };
    assert(khf_filter(shortp, sizeof(shortp), look) == KHF_NONE);            /* too short: untouched */

    uint8_t acl[22] = { 0x02, 0x1A, 0x20, 18 };
    assert(khf_filter(acl, sizeof(acl), look) == KHF_NONE);                  /* not a command */

    uint8_t badlen[22] = { 0x01, 0x1A, 0x20, 17, 0x40, 0x00 };        /* wrong parameter length */
    memcpy(&badlen[6], TOK, 16);
    assert(khf_filter(badlen, sizeof(badlen), look) == KHF_NONE);

    static const uint8_t ITOK[16] = { 'K', 'B', 'T', 'I', 1, 2, 3, 4, 5, 6, 0 };
    uint8_t rl[43] = { 0x01, 0x27, 0x20, 39, 0x00, 1, 2, 3, 4, 5, 6 };
    memcpy(&rl[11], ITOK, 16);
    /* the lookup used here knows only the LTK token: an IRK token is -1 */
    assert(khf_filter(rl, sizeof(rl), look) == KHF_UNKNOWN);

    uint8_t rl_ltk[43] = { 0x01, 0x27, 0x20, 39, 0x00, 1, 2, 3, 4, 5, 6 };
    memcpy(&rl_ltk[11], TOK, 16);   /* an LTK token where an IRK goes is no token */
    assert(khf_filter(rl_ltk, sizeof(rl_ltk), look) == KHF_NONE);

    /* NVS names: one per token, so our LTK, the peer's LTK and the peer's
     * IRK of the same bond never share one */
    uint8_t our_ltk[16]  = { 'K', 'B', 'T', 'L', 1, 2, 3, 4, 5, 6, 0, 0 };
    uint8_t peer_ltk[16] = { 'K', 'B', 'T', 'L', 1, 2, 3, 4, 5, 6, 0, 1 };
    uint8_t peer_irk[16] = { 'K', 'B', 'T', 'I', 1, 2, 3, 4, 5, 6, 0, 1 };
    char a[16];
    char b[16];
    char c[16];
    khf_token_name(our_ltk, a);
    khf_token_name(peer_ltk, b);
    khf_token_name(peer_irk, c);
    assert(strlen(a) == 15U);
    assert(strcmp(a, b) != 0);
    assert(strcmp(a, c) != 0);
    assert(strcmp(b, c) != 0);
    assert(strcmp(a, "l01020304050600") == 0);

    puts("hci filter: ok");
    return 0;
}
