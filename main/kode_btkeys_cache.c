/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_btkeys_cache.c
 * @brief The BLE bond-key table: plain data, no lock, no hardware.
 */
#include <string.h>

#include "kode_btkeys_cache.h"

/** @brief Bytes of a token's magic: "KBTL" or "KBTI". */
#define KBC_MAGIC_LEN  4U

bool kbc_is_token(const uint8_t *t)
{
    return (memcmp(t, KODE_TOKEN_LTK, KBC_MAGIC_LEN) == 0)
           || (memcmp(t, KODE_TOKEN_IRK, KBC_MAGIC_LEN) == 0);
}

bool kbc_put(kbc_t *c, const uint8_t *token, const uint8_t *key)
{
    size_t at = KBC_SLOTS;

    for ( size_t i = 0U; KBC_SLOTS > i; i++ )
    {
        if ( c->slot[i].used && (memcmp(c->slot[i].token, token, KODE_TOKEN_LEN) == 0) )
        {
            at = i;
            break;
        }
        if ( (!c->slot[i].used) && (KBC_SLOTS == at) )
        {
            at = i;
        }
    }
    if ( KBC_SLOTS > at )
    {
        (void)memcpy(c->slot[at].token, token, KODE_TOKEN_LEN);
        (void)memcpy(c->slot[at].key, key, KODE_BTKEY_LEN);
        c->slot[at].used = true;
    }
    return KBC_SLOTS > at;
}

void kbc_del(kbc_t *c, const uint8_t *token)
{
    for ( size_t i = 0U; KBC_SLOTS > i; i++ )
    {
        if ( c->slot[i].used && (memcmp(c->slot[i].token, token, KODE_TOKEN_LEN) == 0) )
        {
            (void)memset(&c->slot[i], 0, sizeof(c->slot[i]));
        }
    }
}

bool kbc_lookup(const kbc_t *c, const uint8_t *token, uint8_t *key_out)
{
    bool found = false;

    for ( size_t i = 0U; (KBC_SLOTS > i) && (!found); i++ )
    {
        if ( c->slot[i].used && (memcmp(c->slot[i].token, token, KODE_TOKEN_LEN) == 0) )
        {
            (void)memcpy(key_out, c->slot[i].key, KODE_BTKEY_LEN);
            found = true;
        }
    }
    return found;
}

uint8_t kbc_count(const kbc_t *c)
{
    uint8_t n = 0U;

    for ( size_t i = 0U; KBC_SLOTS > i; i++ )
    {
        if ( c->slot[i].used )
        {
            n++;
        }
    }
    return n;
}

void kbc_clear(kbc_t *c)
{
    (void)memset(c, 0, sizeof(*c));
}
