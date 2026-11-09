/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_vault_list.c
 * @brief The vault's list of networks: plain data, no hardware.
 */
#include <string.h>

#include "kode_vault_list.h"

/** @brief strlen() bounded by @p max + 1, so an unterminated field stops. */
static size_t bounded_len(const char *s, size_t max)
{
    size_t n = 0U;

    while ( (n <= max) && ('\0' != s[n]) )
    {
        n++;
    }
    return n;
}

bool kv_valid(const char *ssid, const char *pass)
{
    bool ok = false;

    if ( (NULL != ssid) && (NULL != pass) )
    {
        size_t const s = bounded_len(ssid, KODE_SSID_MAX);
        size_t const p = bounded_len(pass, KODE_PASS_MAX);
        ok = (1U <= s) && (KODE_SSID_MAX >= s)
             && ((0U == p) || ((KV_PASS_MIN <= p) && (KODE_PASS_MAX >= p)));
    }
    return ok;
}

int8_t kv_find(const kv_list_t *l, const char *ssid)
{
    int8_t at = KV_ABSENT;

    for ( uint8_t i = 0U; (i < l->count) && (KV_ABSENT == at); i++ )
    {
        if ( strncmp(l->e[i].ssid, ssid, sizeof(l->e[i].ssid)) == 0 )
        {
            at = (int8_t)i;
        }
    }
    return at;
}

/** @brief Take entry @p i out, closing the gap and wiping the last slot. */
static void remove_at(kv_list_t *l, uint8_t i)
{
    for ( uint8_t k = i; (k + 1U) < l->count; k++ )
    {
        l->e[k] = l->e[k + 1U];
    }
    l->count--;
    (void)memset(&l->e[l->count], 0, sizeof(l->e[l->count]));
}

/** @brief Open slot 0 by shifting everything down one; the last falls off. */
static void open_front(kv_list_t *l)
{
    uint8_t n = l->count;

    if ( KODE_VAULT_NETS_MAX == n )
    {
        n = KODE_VAULT_NETS_MAX - 1U;
    }
    for ( uint8_t k = n; 0U < k; k-- )
    {
        l->e[k] = l->e[k - 1U];
    }
    l->count = (uint8_t)(n + 1U);
    (void)memset(&l->e[0], 0, sizeof(l->e[0]));
}

void kv_remember(kv_list_t *l, const char *ssid, const char *pass)
{
    int8_t const at = kv_find(l, ssid);

    if ( KV_ABSENT != at )
    {
        remove_at(l, (uint8_t)at);
    }
    open_front(l);
    (void)strncpy(l->e[0].ssid, ssid, sizeof(l->e[0].ssid) - 1U);
    (void)strncpy(l->e[0].pass, pass, sizeof(l->e[0].pass) - 1U);
}

void kv_touch(kv_list_t *l, const char *ssid)
{
    int8_t const at = kv_find(l, ssid);

    if ( 0 < at )
    {
        kv_entry_t const keep = l->e[at];
        remove_at(l, (uint8_t)at);
        open_front(l);
        l->e[0] = keep;
    }
}

bool kv_forget(kv_list_t *l, const char *ssid)
{
    int8_t const at = kv_find(l, ssid);
    bool found = false;

    if ( KV_ABSENT != at )
    {
        remove_at(l, (uint8_t)at);
        found = true;
    }
    return found;
}
