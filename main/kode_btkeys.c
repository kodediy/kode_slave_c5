/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_btkeys.c
 * @brief BLE bond keys on the C5 (KODE_SVC_BTKEYS), kept in NVS and in a
 *        RAM cache the HCI filter reads; no operation reads a key back.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "nvs.h"

#include "kode_btkeys.h"
#include "kode_btkeys_cache.h"
#include "kode_hci_filter.h"
#include "kode_svc.h"
#include "kode_wire.h"

#define TAG "kode_btkeys"

#define KBK_NS     "kbtkeys"   /**< NVS namespace of the keys. */

/* The table itself is kode_btkeys_cache.c's; this file owns the lock. */
static kbc_t             s_cache;
static portMUX_TYPE      s_lock = portMUX_INITIALIZER_UNLOCKED;

/** @brief Slots used, for INFO. Called with the lock NOT held. */
static void count_refresh(void)
{
    uint8_t n;

    taskENTER_CRITICAL(&s_lock);
    n = kbc_count(&s_cache);
    taskEXIT_CRITICAL(&s_lock);
    kode_svc_set_count(KODE_SVC_BTKEYS, n);
}

/**
 * @brief Put a token and its key in the cache, replacing the same token.
 * @return false when every slot holds another token.
 */
static bool cache_put(const uint8_t *token, const uint8_t *key)
{
    bool ok;

    taskENTER_CRITICAL(&s_lock);
    ok = kbc_put(&s_cache, token, key);
    taskEXIT_CRITICAL(&s_lock);
    return ok;
}

/** @brief Drop a token from the cache. */
static void cache_del(const uint8_t *token)
{
    taskENTER_CRITICAL(&s_lock);
    kbc_del(&s_cache, token);
    taskEXIT_CRITICAL(&s_lock);
}

/** @brief The filter's lookup: RAM only, under the lock. */
static bool lookup(const uint8_t token[KODE_TOKEN_LEN], uint8_t key_out[KODE_BTKEY_LEN])
{
    bool found;

    taskENTER_CRITICAL(&s_lock);
    found = kbc_lookup(&s_cache, token, key_out);
    taskEXIT_CRITICAL(&s_lock);
    return found;
}

void kode_btkeys_filter(uint8_t *pkt, uint16_t len)
{
    khf_result_t const rc = khf_filter(pkt, len, &lookup);
    if ( KHF_SWAPPED == rc )
    {
        kode_svc_add_swap(true);
    }
    else if ( KHF_UNKNOWN == rc )
    {
        kode_svc_add_swap(false);
    }
    else
    {
        /* no token in this packet */
    }
}

static uint8_t op_put(const uint8_t *req, uint16_t len)
{
    kode_btkey_t const *const k = (kode_btkey_t const *)req;
    nvs_handle_t h;
    char         name[KHF_NAME_LEN];
    esp_err_t    err;

    if ( (sizeof(kode_btkey_t) != len) || !kbc_is_token(k->token) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    if ( !cache_put(k->token, k->key) )
    {
        ESP_LOGW(TAG, "every key slot is taken; a bond's key was refused");
        return KODE_ST_REFUSED;
    }
    khf_token_name(k->token, name);
    err = nvs_open(KBK_NS, NVS_READWRITE, &h);
    if ( ESP_OK == err )
    {
        err = nvs_set_blob(h, name, k, sizeof(*k));
        if ( ESP_OK == err )
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    count_refresh();
    if ( ESP_OK != err )
    {
        ESP_LOGW(TAG, "a bond's key is kept for this boot only: %s", esp_err_to_name(err));
        return KODE_ST_STORAGE;
    }
    return KODE_ST_OK;
}

static uint8_t op_del(const uint8_t *req, uint16_t len)
{
    nvs_handle_t h;
    char         name[KHF_NAME_LEN];

    if ( (KODE_TOKEN_LEN != len) || !kbc_is_token(req) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    cache_del(req);
    khf_token_name(req, name);
    if ( nvs_open(KBK_NS, NVS_READWRITE, &h) == ESP_OK )
    {
        (void)nvs_erase_key(h, name);
        (void)nvs_commit(h);
        nvs_close(h);
    }
    count_refresh();
    return KODE_ST_OK;
}

/**
 * @brief Whether this chip holds the key behind a token.
 *
 * The P4 asks before it forgets a bond whose encryption failed: a key that
 * is here means the failure was the peer's (or a device spoofing it), and
 * the bond stays.
 */
static uint8_t op_has(const uint8_t *req, uint16_t len)
{
    uint8_t      key[KODE_BTKEY_LEN];
    nvs_handle_t h;
    char         name[KHF_NAME_LEN];
    size_t       n = 0U;
    bool         has;

    if ( (KODE_TOKEN_LEN != len) || !kbc_is_token(req) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    has = lookup(req, key);
    (void)memset(key, 0, sizeof(key));
    if ( !has )
    {
        khf_token_name(req, name);
        if ( nvs_open(KBK_NS, NVS_READONLY, &h) == ESP_OK )
        {
            has = (nvs_get_blob(h, name, NULL, &n) == ESP_OK) && (0U < n);
            nvs_close(h);
        }
    }
    if ( has )
    {
        return KODE_ST_OK;
    }
    return KODE_ST_NOT_FOUND;
}

static uint8_t op_wipe(void)
{
    nvs_handle_t h;
    esp_err_t    err = nvs_open(KBK_NS, NVS_READWRITE, &h);

    taskENTER_CRITICAL(&s_lock);
    kbc_clear(&s_cache);
    taskEXIT_CRITICAL(&s_lock);
    if ( ESP_OK == err )
    {
        err = nvs_erase_all(h);
        if ( ESP_OK == err )
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    count_refresh();
    ESP_LOGI(TAG, "every BLE key forgotten");
    if ( (ESP_OK != err) && (ESP_ERR_NVS_NOT_FOUND != err) )
    {
        return KODE_ST_STORAGE;
    }
    return KODE_ST_OK;
}

/** @brief KODE_SVC_BTKEYS's handler (kode_svc.h). */
static uint8_t btkeys_handle(uint8_t op, const uint8_t *req, uint16_t len,
                             uint8_t *out, uint16_t *out_len)
{
    uint8_t st = KODE_ST_BAD_REQUEST;

    (void)out;
    *out_len = 0U;
    if ( KODE_BTKEYS_PUT == op )
    {
        st = op_put(req, len);
    }
    else if ( KODE_BTKEYS_DEL == op )
    {
        st = op_del(req, len);
    }
    else if ( (KODE_BTKEYS_WIPE == op) && (0U == len) )
    {
        st = op_wipe();
    }
    else if ( KODE_BTKEYS_HAS == op )
    {
        st = op_has(req, len);
    }
    else
    {
        st = KODE_ST_BAD_REQUEST;
    }
    return st;
}

/** @brief Every key NVS keeps, into the cache. */
static void load_all(void)
{
    nvs_iterator_t it = NULL;
    nvs_handle_t   h;

    if ( nvs_entry_find(NVS_DEFAULT_PART_NAME, KBK_NS, NVS_TYPE_BLOB, &it) != ESP_OK )
    {
        return;
    }
    if ( nvs_open(KBK_NS, NVS_READONLY, &h) == ESP_OK )
    {
        esp_err_t more = ESP_OK;
        while ( ESP_OK == more )
        {
            nvs_entry_info_t info;
            kode_btkey_t     k;
            size_t           n = sizeof(k);
            (void)nvs_entry_info(it, &info);
            if ( (nvs_get_blob(h, info.key, &k, &n) == ESP_OK) && (sizeof(k) == n)
                && kbc_is_token(k.token) )
            {
                (void)cache_put(k.token, k.key);
            }
            (void)memset(&k, 0, sizeof(k));
            more = nvs_entry_next(&it);
        }
        nvs_close(h);
    }
    nvs_release_iterator(it);
}

void kode_btkeys_init(void)
{
    load_all();
    count_refresh();
    kode_svc_register(KODE_SVC_BTKEYS, &btkeys_handle);
}
