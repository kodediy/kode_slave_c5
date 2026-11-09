/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_btkeys_cache.c
 * @brief The C5's table of BLE bond keys: twelve slots, one per token, a
 *        full table refuses, and a dropped key leaves no bytes behind.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_btkeys_cache.h"
#include "../main/kode_wire.h"

/** @brief A token: an LTK's magic, then @p n in the identity bytes. */
static void make_token(uint8_t t[KODE_TOKEN_LEN], uint8_t n)
{
    (void)memset(t, 0, KODE_TOKEN_LEN);
    (void)memcpy(t, KODE_TOKEN_LTK, 4U);
    t[4] = n;
}

/** @brief A key whose every byte is @p fill. */
static void make_key(uint8_t k[KODE_BTKEY_LEN], uint8_t fill)
{
    (void)memset(k, fill, KODE_BTKEY_LEN);
}

int main(void)
{
    kbc_t   c;
    uint8_t t[KODE_TOKEN_LEN];
    uint8_t k[KODE_BTKEY_LEN];
    uint8_t got[KODE_BTKEY_LEN];

    (void)memset(&c, 0, sizeof(c));
    assert(kbc_count(&c) == 0U);

    /* What a token is: either magic first. */
    make_token(t, 1U);
    assert(kbc_is_token(t));
    (void)memcpy(t, KODE_TOKEN_IRK, 4U);
    assert(kbc_is_token(t));
    (void)memcpy(t, "KBTX", 4U);
    assert(!kbc_is_token(t));
    (void)memset(t, 0, KODE_TOKEN_LEN);
    assert(!kbc_is_token(t));

    /* Fill every slot. */
    for ( uint8_t i = 0U; KBC_SLOTS > i; i++ )
    {
        make_token(t, i);
        make_key(k, (uint8_t)(0x10U + i));
        assert(kbc_put(&c, t, k));
    }
    assert(kbc_count(&c) == KBC_SLOTS);

    /* The next token is refused and changes nothing. */
    make_token(t, KBC_SLOTS);
    make_key(k, 0xEEU);
    assert(!kbc_put(&c, t, k));
    assert(kbc_count(&c) == KBC_SLOTS);
    assert(!kbc_lookup(&c, t, got));

    /* The same token again replaces its key without growing, even when full. */
    make_token(t, 3U);
    make_key(k, 0xA5U);
    assert(kbc_put(&c, t, k));
    assert(kbc_count(&c) == KBC_SLOTS);
    assert(kbc_lookup(&c, t, got));
    assert(memcmp(got, k, KODE_BTKEY_LEN) == 0);

    /* Another token's key is untouched. */
    make_token(t, 4U);
    assert(kbc_lookup(&c, t, got));
    make_key(k, 0x14U);
    assert(memcmp(got, k, KODE_BTKEY_LEN) == 0);

    /* Delete frees a slot; the token misses; a new token takes it. */
    make_token(t, 5U);
    kbc_del(&c, t);
    assert(kbc_count(&c) == (KBC_SLOTS - 1U));
    assert(!kbc_lookup(&c, t, got));
    make_token(t, KBC_SLOTS);
    make_key(k, 0xEEU);
    assert(kbc_put(&c, t, k));
    assert(kbc_count(&c) == KBC_SLOTS);
    assert(kbc_lookup(&c, t, got));
    assert(memcmp(got, k, KODE_BTKEY_LEN) == 0);

    /* Deleting a token that is not there does nothing. */
    make_token(t, 99U);
    kbc_del(&c, t);
    assert(kbc_count(&c) == KBC_SLOTS);

    /* A deleted slot holds no key bytes: the whole table has none of them. */
    kbc_t d;
    (void)memset(&d, 0, sizeof(d));
    make_token(t, 1U);
    make_key(k, 0x77U);
    assert(kbc_put(&d, t, k));
    kbc_del(&d, t);
    uint8_t zero[sizeof(d)];
    (void)memset(zero, 0, sizeof(zero));
    assert(memcmp(&d, zero, sizeof(d)) == 0);
    assert(!kbc_lookup(&d, t, got));

    /* Wipe empties the table, keys included. */
    kbc_clear(&c);
    assert(kbc_count(&c) == 0U);
    (void)memset(zero, 0, sizeof(zero));
    assert(memcmp(&c, zero, sizeof(c)) == 0);

    puts("btkeys cache: ok");
    return 0;
}
