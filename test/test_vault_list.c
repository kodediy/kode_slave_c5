/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_vault_list.c
 * @brief The vault's list on the host: most recent first, eight at most, the
 *        oldest out, and the edges of what a Wi-Fi credential may be.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_vault_list.h"

int main(void)
{
    kv_list_t l;
    (void)memset(&l, 0, sizeof(l));

    kv_remember(&l, "a", "password1");
    kv_remember(&l, "b", "");                       /* an open network */
    assert((2U == l.count) && (strcmp(l.e[0].ssid, "b") == 0));

    kv_remember(&l, "a", "password2");              /* refreshed: to the front */
    assert((2U == l.count) && (strcmp(l.e[0].ssid, "a") == 0));
    assert(strcmp(l.e[0].pass, "password2") == 0);

    for ( uint8_t i = 0U; KODE_VAULT_NETS_MAX > i; i++ )
    {
        char s[8];
        (void)snprintf(s, sizeof(s), "n%u", (unsigned)i);
        kv_remember(&l, s, "password0");
    }
    assert(KODE_VAULT_NETS_MAX == l.count);
    assert(kv_find(&l, "b") == KV_ABSENT);                 /* the oldest went */
    assert(kv_find(&l, "a") == KV_ABSENT);
    assert(kv_find(&l, "n7") == 0);

    kv_touch(&l, "n0");
    assert(strcmp(l.e[0].ssid, "n0") == 0);
    assert(kv_forget(&l, "n0") && !kv_forget(&l, "n0"));
    assert(7U == l.count);

    /* The vacated slot keeps neither the name nor the password. */
    uint8_t const vacated = l.count;
    uint8_t zero[sizeof(l.e[0])];
    (void)memset(zero, 0, sizeof(zero));
    assert(memcmp(&l.e[vacated], zero, sizeof(zero)) == 0);
    {
        kv_list_t f;
        (void)memset(&f, 0, sizeof(f));
        kv_remember(&f, "keep", "password1");
        kv_remember(&f, "drop", "secret-pass");
        assert(kv_forget(&f, "keep"));              /* the older, so the last slot moves */
        assert((1U == f.count) && (strcmp(f.e[0].ssid, "drop") == 0));
        assert(memcmp(&f.e[1], zero, sizeof(zero)) == 0);
        assert(kv_forget(&f, "drop"));
        assert(memcmp(&f.e[0], zero, sizeof(zero)) == 0);
    }

    /* The edges of a credential. */
    char psk[65];
    (void)memset(psk, 'a', 64);
    psk[64] = '\0';
    assert(kv_valid("x", psk));                     /* a 64-hex PSK */
    assert(kv_valid("x", ""));                      /* open */
    assert(!kv_valid("x", "short"));                /* 1..7 is no passphrase */
    assert(kv_valid("x", "12345678"));              /* the shortest WPA one */
    assert(kv_valid("Caf\xC3\xA9 de la esquina 2.4 GHz!!", "password1"));
    char s32[33];
    (void)memset(s32, 's', 32);
    s32[32] = '\0';
    assert(kv_valid(s32, "password1"));             /* 32 bytes: the most */
    char s33[34];
    (void)memset(s33, 's', 33);
    s33[33] = '\0';
    assert(!kv_valid(s33, "password1"));
    assert(!kv_valid("", "password1"));
    assert(!kv_valid(NULL, "password1"));
    assert(!kv_valid("x", NULL));
    char p65[66];
    (void)memset(p65, 'p', 65);
    p65[65] = '\0';
    assert(!kv_valid("x", p65));

    puts("vault list: ok");
    return 0;
}
