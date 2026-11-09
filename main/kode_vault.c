/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_vault.c
 * @brief The Wi-Fi vault (KODE_SVC_VAULT): the passwords of the networks the
 *        board knows, kept on the C5, used to join and never handed back.
 */
#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs.h"

#include "kode_svc.h"
#include "kode_vault.h"
#include "kode_vault_list.h"
#include "kode_wire.h"

#define TAG "kode_vault"

#define KV_NS       "kvault"       /**< NVS namespace of the vault.        */
#define KV_KEY      "nets"         /**< The one blob, a kv_blob_t.         */
#define KV_MAGIC    0x544C564BUL   /**< "KVLT".                            */
#define KV_VERSION  1U             /**< Another reads as an empty vault.   */

/** @brief What NVS holds. */
typedef struct {
    uint32_t  magic;      /**< KV_MAGIC.                                     */
    uint16_t  version;    /**< KV_VERSION.                                   */
    uint16_t  reserved;   /**< 0.                                            */
    kv_list_t list;       /**< The networks.                                 */
} kv_blob_t;

static kv_blob_t s_blob;
static bool      s_sta_in_ram;   /* the station's config is kept in RAM only */

/**
 * @brief Keep the station's config out of flash, and clear what is there.
 *
 * esp_wifi_set_config() saves the config, password and all, in the Wi-Fi
 * stack's own NVS unless told otherwise, and that copy would outlive a
 * forget or a wipe. So the stack writes an empty config to flash once, and
 * keeps every config after it in RAM. Needs the stack started: before that
 * it is tried again on the next join or wipe.
 */
static void sta_keep_in_ram(void)
{
    wifi_config_t empty;

    if ( s_sta_in_ram )
    {
        return;
    }
    (void)memset(&empty, 0, sizeof(empty));
    if ( esp_wifi_set_storage(WIFI_STORAGE_FLASH) == ESP_OK )
    {
        (void)esp_wifi_set_config(WIFI_IF_STA, &empty);
        if ( esp_wifi_set_storage(WIFI_STORAGE_RAM) == ESP_OK )
        {
            s_sta_in_ram = true;
            ESP_LOGI(TAG, "the station's config stays in RAM");
        }
    }
}

/** @brief Write the list back; on failure the RAM copy stays as it is. */
static uint8_t vault_save(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(KV_NS, NVS_READWRITE, &h);

    if ( ESP_OK == err )
    {
        s_blob.magic   = KV_MAGIC;
        s_blob.version = KV_VERSION;
        err = nvs_set_blob(h, KV_KEY, &s_blob, sizeof(s_blob));
        if ( ESP_OK == err )
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    kode_svc_set_count(KODE_SVC_VAULT, s_blob.list.count);
    if ( ESP_OK != err )
    {
        ESP_LOGE(TAG, "the vault could not be saved: %s", esp_err_to_name(err));
        return KODE_ST_STORAGE;
    }
    return KODE_ST_OK;
}

/** @brief A name field from the wire, checked for its NUL. */
static bool ssid_ok(const char ssid[KODE_SSID_MAX + 1U])
{
    return (memchr(ssid, '\0', KODE_SSID_MAX + 1U) != NULL) && ('\0' != ssid[0]);
}

static uint8_t op_remember(const uint8_t *req, uint16_t len)
{
    kode_vault_cred_t c;

    if ( sizeof(c) != len )
    {
        return KODE_ST_BAD_REQUEST;
    }
    (void)memcpy(&c, req, sizeof(c));
    if ( (memchr(c.ssid, '\0', sizeof(c.ssid)) == NULL)
        || (memchr(c.pass, '\0', sizeof(c.pass)) == NULL)
        || !kv_valid(c.ssid, c.pass) )
    {
        (void)memset(&c, 0, sizeof(c));
        return KODE_ST_BAD_REQUEST;
    }
    kv_remember(&s_blob.list, c.ssid, c.pass);
    ESP_LOGI(TAG, "remembered '%s' (%u saved)", c.ssid, (unsigned)s_blob.list.count);
    (void)memset(&c, 0, sizeof(c));
    return vault_save();
}

static uint8_t op_join(const uint8_t *req, uint16_t len)
{
    kode_vault_ssid_t s;
    wifi_config_t     wc;

    if ( sizeof(s) != len )
    {
        return KODE_ST_BAD_REQUEST;
    }
    (void)memcpy(&s, req, sizeof(s));
    if ( !ssid_ok(s.ssid) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    int8_t const at = kv_find(&s_blob.list, s.ssid);
    if ( KV_ABSENT == at )
    {
        return KODE_ST_NOT_FOUND;
    }
    sta_keep_in_ram();
    (void)memset(&wc, 0, sizeof(wc));
    (void)memcpy(wc.sta.ssid, s_blob.list.e[at].ssid, KODE_SSID_MAX);
    (void)memcpy(wc.sta.password, s_blob.list.e[at].pass, KODE_PASS_MAX);
    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &wc);
    (void)memset(&wc, 0, sizeof(wc));
    if ( ESP_OK == err )
    {
        err = esp_wifi_connect();
    }
    if ( ESP_OK != err )
    {
        ESP_LOGW(TAG, "joining '%s' was refused: %s", s.ssid, esp_err_to_name(err));
        return KODE_ST_REFUSED;
    }
    kv_touch(&s_blob.list, s.ssid);
    (void)vault_save();
    ESP_LOGI(TAG, "joining '%s' from the vault", s.ssid);
    return KODE_ST_OK;
}

static uint8_t op_list(uint8_t *out, uint16_t *out_len)
{
    kode_vault_list_t l;

    (void)memset(&l, 0, sizeof(l));
    l.count = s_blob.list.count;
    for ( uint8_t i = 0U; i < l.count; i++ )
    {
        (void)memcpy(l.ssid[i], s_blob.list.e[i].ssid, sizeof(l.ssid[i]));
    }
    (void)memcpy(out, &l, sizeof(l));
    *out_len = (uint16_t)sizeof(l);
    return KODE_ST_OK;
}

static uint8_t op_forget(const uint8_t *req, uint16_t len)
{
    kode_vault_ssid_t s;

    if ( sizeof(s) != len )
    {
        return KODE_ST_BAD_REQUEST;
    }
    (void)memcpy(&s, req, sizeof(s));
    if ( !ssid_ok(s.ssid) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    if ( !kv_forget(&s_blob.list, s.ssid) )
    {
        return KODE_ST_NOT_FOUND;
    }
    ESP_LOGI(TAG, "forgot '%s'", s.ssid);
    return vault_save();
}

static uint8_t op_wipe(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(KV_NS, NVS_READWRITE, &h);

    sta_keep_in_ram();   /* and the copy the Wi-Fi stack kept goes too */

    (void)memset(&s_blob, 0, sizeof(s_blob));
    kode_svc_set_count(KODE_SVC_VAULT, 0U);
    if ( ESP_OK == err )
    {
        err = nvs_erase_key(h, KV_KEY);
        if ( (ESP_OK == err) || (ESP_ERR_NVS_NOT_FOUND == err) )
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    if ( ESP_OK != err )
    {
        ESP_LOGE(TAG, "the vault could not be wiped: %s", esp_err_to_name(err));
        return KODE_ST_STORAGE;
    }
    ESP_LOGI(TAG, "wiped");
    return KODE_ST_OK;
}

/** @brief KODE_SVC_VAULT's handler (kode_svc.h). */
static uint8_t vault_handle(uint8_t op, const uint8_t *req, uint16_t len,
                            uint8_t *out, uint16_t *out_len)
{
    uint8_t st = KODE_ST_BAD_REQUEST;

    *out_len = 0U;
    if ( KODE_VAULT_REMEMBER == op )
    {
        st = op_remember(req, len);
    }
    else if ( KODE_VAULT_JOIN == op )
    {
        st = op_join(req, len);
    }
    else if ( (KODE_VAULT_LIST == op) && (0U == len) )
    {
        st = op_list(out, out_len);
    }
    else if ( KODE_VAULT_FORGET == op )
    {
        st = op_forget(req, len);
    }
    else if ( (KODE_VAULT_WIPE == op) && (0U == len) )
    {
        st = op_wipe();
    }
    else
    {
        st = KODE_ST_BAD_REQUEST;
    }
    return st;
}

void kode_vault_init(void)
{
    nvs_handle_t h;
    size_t len = sizeof(s_blob);

    (void)memset(&s_blob, 0, sizeof(s_blob));
    if ( nvs_open(KV_NS, NVS_READONLY, &h) == ESP_OK )
    {
        if ( (nvs_get_blob(h, KV_KEY, &s_blob, &len) != ESP_OK)
            || (sizeof(s_blob) != len) || (KV_MAGIC != s_blob.magic)
            || (KV_VERSION != s_blob.version) || (KODE_VAULT_NETS_MAX < s_blob.list.count) )
        {
            (void)memset(&s_blob, 0, sizeof(s_blob));
        }
        nvs_close(h);
    }
    kode_svc_set_count(KODE_SVC_VAULT, s_blob.list.count);
    kode_svc_register(KODE_SVC_VAULT, &vault_handle);
    ESP_LOGI(TAG, "%u networks saved", (unsigned)s_blob.list.count);
}
