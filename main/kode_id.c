/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_id.c
 * @brief The unit's identity on the C5 (KODE_SVC_ID, kode_wire.h): a Key
 *        Manager key that signs its own CSR and the cloud's challenge only.
 */
#include <stddef.h>
#include <string.h>

#include "esp_key_mgr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "psa_crypto_driver_esp_ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/psa_util.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "soc/soc_caps.h"

#include "kode_id.h"
#include "kode_id_nonce.h"
#include "kode_id_serial.h"
#include "kode_svc.h"
#include "kode_wire.h"

/* ESP-IDF takes the Key Manager out after v6.1, and the key would go with it. */
#if !SOC_KEY_MANAGER_SUPPORTED
#error "This ESP-IDF has no Key Manager for the identity's key: build with v6.1 (kodediy/kode_slave_c5#4)"
#endif

#define TAG "kode_id"

/* Its own partition: app_main() may erase the default one, which would lose
 * the key. Nothing in it is secret, so it is not encrypted. */
#define KID_PART      "fctry"   /**< NVS partition of the identity.         */
#define KID_NS        "kid"     /**< Its namespace.                         */
#define KID_KEY_RI    "ri"      /**< The Key Manager's recovery information. */
#define KID_KEY_CERT  "cert"    /**< The unit certificate and its chain.    */
#define KID_KEY_LOCK  "lock"    /**< Present once LOCK closed CSR and CERT_SET. */

#define KID_DEPLOYS        2U    /**< Key Manager deploys per new key; the last is kept. */
#define KID_KEY_BITS       256U  /**< P-256.                                */
#define KID_SUBJECT_LEN    40U   /**< "CN=<serial>,O=Kode" and its NUL.     */
#define KID_PUBKEY_DER_MAX 128U  /**< A P-256 public key in DER, with room. */
#define KID_HASH_LEN       32U   /**< SHA-256.                              */
#define KID_SIG_RAW_LEN    64U   /**< r and s of a P-256 signature.         */
#define KID_SIG_DER_MAX    72U   /**< The same signature in DER, at most.   */

static esp_key_mgr_key_recovery_info_t s_ri;   /* what loads the key again */
static psa_key_id_t s_key;
static bool         s_loaded;
static uint8_t      s_flags;                   /* KODE_ID_F_*             */
static bool         s_ready;                   /* KID_PART is readable    */

/* ---- NVS ------------------------------------------------------------------ */

/**
 * @brief Whether a key exists under @p key in the identity namespace.
 * @param has Set to the answer when there is one.
 * @return false when the store could not say (a read error, not an absence).
 */
static bool nvs_has(const char *key, bool *has)
{
    nvs_handle_t h;
    size_t       len = 0U;
    bool         known = true;
    esp_err_t    err = nvs_open_from_partition(KID_PART, KID_NS, NVS_READONLY, &h);

    *has = false;
    if ( ESP_OK == err )
    {
        err = nvs_get_blob(h, key, NULL, &len);
        nvs_close(h);
        if ( ESP_OK == err )
        {
            *has = (0U < len);
        }
        else if ( ESP_ERR_NVS_NOT_FOUND != err )
        {
            known = false;
        }
        else
        {
            /* not there */
        }
    }
    else if ( ESP_ERR_NVS_NOT_FOUND != err )
    {
        known = false;   /* a namespace never written is an absence */
    }
    else
    {
        /* not there */
    }
    return known;
}

/**
 * @brief Recompute the state flags and hand them to INFO.
 *
 * A flag the store cannot read keeps its last value: a passing read error
 * must not unlock an identity that was locked.
 */
static void flags_refresh(void)
{
    static const struct {
        const char *key;
        uint8_t     bit;
    } FLAGS[] = {
        { KID_KEY_RI,   KODE_ID_F_KEY },
        { KID_KEY_CERT, KODE_ID_F_CERT },
        { KID_KEY_LOCK, KODE_ID_F_LOCKED },
    };
    uint8_t flags = 0U;

    for ( size_t i = 0U; (sizeof(FLAGS) / sizeof(FLAGS[0])) > i; i++ )
    {
        bool has = false;

        if ( !nvs_has(FLAGS[i].key, &has) )
        {
            flags |= (uint8_t)(s_flags & FLAGS[i].bit);
        }
        else if ( has )
        {
            flags |= FLAGS[i].bit;
        }
        else
        {
            /* absent */
        }
    }
    s_flags = flags;
    kode_svc_set_count(KODE_SVC_ID, s_flags);
}

/* ---- The key -------------------------------------------------------------- */

/**
 * @brief Load the Key Manager key as a PSA opaque key, creating it first
 *        when asked to and none exists.
 * @param create true for CSR (the one place a key is born).
 * @return KODE_ST_OK, KODE_ST_NOT_FOUND (no key and not creating) or
 *         KODE_ST_STORAGE.
 */
static uint8_t key_load(bool create)
{
    nvs_handle_t h;
    size_t       n   = sizeof(s_ri);
    esp_err_t    err;

    if ( s_loaded )
    {
        return KODE_ST_OK;
    }
    err = nvs_open_from_partition(KID_PART, KID_NS, NVS_READWRITE, &h);
    if ( ESP_OK != err )
    {
        return KODE_ST_STORAGE;
    }
    err = nvs_get_blob(h, KID_KEY_RI, &s_ri, &n);
    if ( (ESP_OK == err) && (sizeof(s_ri) != n) )
    {
        err = ESP_ERR_NVS_INVALID_LENGTH;
    }
    if ( (ESP_OK != err) && (ESP_ERR_NVS_NOT_FOUND != err) )
    {
        /* A record that is there and cannot be read is not "no key": making
         * a new one would void the certificate of the one that exists. */
        nvs_close(h);
        return KODE_ST_STORAGE;
    }
    if ( ESP_OK != err )
    {
        if ( !create )
        {
            nvs_close(h);
            return KODE_ST_NOT_FOUND;
        }
        esp_key_mgr_random_key_config_t cfg = {
            .key_type = ESP_KEY_MGR_ECDSA_KEY,
            .key_len  = ESP_KEY_MGR_ECDSA_LEN_256,
        };
        /* Each deploy overwrites s_ri, so the first key is thrown away
         * unused: two C5s made the same one. */
        err = ESP_OK;
        for ( uint32_t i = 0U; (KID_DEPLOYS > i) && (ESP_OK == err); i++ )
        {
            err = esp_key_mgr_deploy_key_in_random_mode(&cfg, &s_ri);
        }
        ESP_LOGI(TAG, "a new identity key in the Key Manager: %s", esp_err_to_name(err));
        if ( ESP_OK == err )
        {
            err = nvs_set_blob(h, KID_KEY_RI, &s_ri, sizeof(s_ri));
        }
        if ( ESP_OK == err )
        {
            /* A new key voids any certificate made for the old one. */
            (void)nvs_erase_key(h, KID_KEY_CERT);
            err = nvs_commit(h);
        }
    }
    nvs_close(h);
    if ( ESP_OK != err )
    {
        return KODE_ST_STORAGE;
    }

    (void)psa_crypto_init();
    esp_ecdsa_opaque_key_t opaque = {
        .curve             = ESP_ECDSA_CURVE_SECP256R1,
        .key_recovery_info = &s_ri,
    };
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, KID_KEY_BITS);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_ESP_ECDSA_VOLATILE);
    psa_status_t const st = psa_import_key(&a, (const uint8_t *)&opaque,
                                           sizeof(opaque), &s_key);
    psa_reset_key_attributes(&a);
    if ( PSA_SUCCESS != st )
    {
        ESP_LOGE(TAG, "the identity key would not load: %d", (int)st);
        return KODE_ST_STORAGE;
    }
    s_loaded = true;
    flags_refresh();
    return KODE_ST_OK;
}

/* ---- Operations ----------------------------------------------------------- */

static uint8_t op_csr(uint8_t *out, uint16_t *out_len)
{
    mbedtls_pk_context    pk;
    mbedtls_x509write_csr csr;
    uint8_t mac[KID_MAC_LEN];
    char    serial[KID_SERIAL_LEN];
    char    subject[KID_SUBJECT_LEN];
    uint8_t st;

    if ( (s_flags & KODE_ID_F_LOCKED) != 0U )
    {
        return KODE_ST_LOCKED;
    }
    st = key_load(true);
    if ( KODE_ST_OK != st )
    {
        return st;
    }
    if ( esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK )
    {
        return KODE_ST_STORAGE;
    }
    kid_serial_of(mac, serial);
    (void)snprintf(subject, sizeof(subject), "CN=%s,O=Kode", serial);

    mbedtls_pk_init(&pk);
    mbedtls_x509write_csr_init(&csr);
    int rc = mbedtls_pk_wrap_psa(&pk, s_key);
    if ( 0 == rc )
    {
        mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
        mbedtls_x509write_csr_set_key(&csr, &pk);
        rc = mbedtls_x509write_csr_set_subject_name(&csr, subject);
    }
    if ( 0 == rc )
    {
        /* Written at the END of the buffer; the length comes back. */
        rc = mbedtls_x509write_csr_der(&csr, out, KODE_MAX_PAYLOAD);
    }
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&pk);
    if ( 0 >= rc )
    {
        ESP_LOGE(TAG, "the CSR could not be built: -0x%04x", (unsigned)(-rc));
        return KODE_ST_STORAGE;
    }
    (void)memmove(out, &out[KODE_MAX_PAYLOAD - (size_t)rc], (size_t)rc);
    *out_len = (uint16_t)rc;
    ESP_LOGI(TAG, "CSR for %s, %d bytes", serial, rc);
    return KODE_ST_OK;
}

/** @brief Whether a certificate's public key is this chip's key. */
static bool cert_is_ours(const uint8_t *der, size_t len)
{
    mbedtls_x509_crt   crt;
    mbedtls_pk_context ours;
    uint8_t            a[KID_PUBKEY_DER_MAX];
    uint8_t            b[KID_PUBKEY_DER_MAX];
    bool               same = false;

    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&ours);
    if ( (mbedtls_x509_crt_parse_der(&crt, der, len) == 0)
        && (mbedtls_pk_wrap_psa(&ours, s_key) == 0) )
    {
        int const na = mbedtls_pk_write_pubkey_der(&crt.pk, a, sizeof(a));
        int const nb = mbedtls_pk_write_pubkey_der(&ours, b, sizeof(b));
        same = (0 < na) && (na == nb)
               && (memcmp(&a[sizeof(a) - (size_t)na], &b[sizeof(b) - (size_t)nb],
                          (size_t)na) == 0);
    }
    mbedtls_pk_free(&ours);
    mbedtls_x509_crt_free(&crt);
    return same;
}

static uint8_t op_cert_set(const uint8_t *req, uint16_t len)
{
    kode_id_cert_t const *const c = (kode_id_cert_t const *)req;
    nvs_handle_t h;
    esp_err_t    err;

    if ( (s_flags & KODE_ID_F_LOCKED) != 0U )
    {
        return KODE_ST_LOCKED;
    }
    if ( (offsetof(kode_id_cert_t, der) > len)
        || (((size_t)c->unit_len + (size_t)c->chain_len) > sizeof(c->der))
        || ((size_t)len != (offsetof(kode_id_cert_t, der) + (size_t)c->unit_len
                            + (size_t)c->chain_len))
        || (0U == c->unit_len) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    if ( key_load(false) != KODE_ST_OK )
    {
        return KODE_ST_NOT_FOUND;
    }
    if ( !cert_is_ours(c->der, c->unit_len) )
    {
        ESP_LOGW(TAG, "a certificate for another key was refused");
        return KODE_ST_REFUSED;
    }
    err = nvs_open_from_partition(KID_PART, KID_NS, NVS_READWRITE, &h);
    if ( ESP_OK == err )
    {
        err = nvs_set_blob(h, KID_KEY_CERT, req, len);
        if ( ESP_OK == err )
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    flags_refresh();
    if ( ESP_OK != err )
    {
        return KODE_ST_STORAGE;
    }
    ESP_LOGI(TAG, "certificate kept (%u + %u bytes)", (unsigned)c->unit_len,
             (unsigned)c->chain_len);
    return KODE_ST_OK;
}

static uint8_t op_cert_get(uint8_t *out, uint16_t *out_len)
{
    nvs_handle_t h;
    size_t       n   = KODE_MAX_PAYLOAD;
    esp_err_t    err = nvs_open_from_partition(KID_PART, KID_NS, NVS_READONLY, &h);

    if ( ESP_OK == err )
    {
        err = nvs_get_blob(h, KID_KEY_CERT, out, &n);
        nvs_close(h);
    }
    if ( ESP_OK != err )
    {
        return KODE_ST_NOT_FOUND;
    }
    *out_len = (uint16_t)n;
    return KODE_ST_OK;
}

static uint8_t op_sign_auth(const uint8_t *req, uint16_t len, uint8_t *out, uint16_t *out_len)
{
    kode_id_nonce_t const *const q = (kode_id_nonce_t const *)req;
    uint8_t msg[sizeof(KID_AUTH_PREFIX) + KODE_NONCE_MAX];
    uint8_t hash[KID_HASH_LEN];
    uint8_t raw[KID_SIG_RAW_LEN];
    size_t  n = 0U;

    if ( (sizeof(kode_id_nonce_t) != len) || !kode_nonce_ok(q->nonce, q->len) )
    {
        return KODE_ST_BAD_REQUEST;
    }
    if ( key_load(false) != KODE_ST_OK )
    {
        return KODE_ST_NOT_FOUND;
    }
    size_t const mlen = kid_auth_message(q->nonce, q->len, msg, sizeof(msg));
    if ( (0U == mlen)
        || (psa_hash_compute(PSA_ALG_SHA_256, msg, mlen, hash, sizeof(hash), &n) != PSA_SUCCESS)
        || (psa_sign_hash(s_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash),
                          raw, sizeof(raw), &n) != PSA_SUCCESS)
        || (sizeof(raw) != n) )
    {
        return KODE_ST_STORAGE;
    }
    size_t der_len = 0U;
    if ( mbedtls_ecdsa_raw_to_der(KID_KEY_BITS, raw, sizeof(raw), out, KID_SIG_DER_MAX, &der_len) != 0 )
    {
        return KODE_ST_STORAGE;
    }
    *out_len = (uint16_t)der_len;
    return KODE_ST_OK;
}

static uint8_t op_lock(void)
{
    nvs_handle_t h;
    uint8_t      one = 1U;
    esp_err_t    err;

    if ( (s_flags & KODE_ID_F_CERT) == 0U )
    {
        return KODE_ST_REFUSED;   /* nothing to lock yet */
    }
    err = nvs_open_from_partition(KID_PART, KID_NS, NVS_READWRITE, &h);
    if ( ESP_OK == err )
    {
        err = nvs_set_blob(h, KID_KEY_LOCK, &one, sizeof(one));
        if ( ESP_OK == err )
        {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    flags_refresh();
    if ( ESP_OK != err )
    {
        return KODE_ST_STORAGE;
    }
    ESP_LOGI(TAG, "identity locked: no new key, no new certificate");
    return KODE_ST_OK;
}

/** @brief KODE_SVC_ID's handler (kode_svc.h). */
static uint8_t id_handle(uint8_t op, const uint8_t *req, uint16_t len,
                         uint8_t *out, uint16_t *out_len)
{
    uint8_t st = KODE_ST_BAD_REQUEST;

    *out_len = 0U;
    if ( !s_ready )
    {
        st = KODE_ST_STORAGE;   /* the identity's partition would not open */
    }
    else if ( (KODE_ID_CSR == op) && (0U == len) )
    {
        st = op_csr(out, out_len);
    }
    else if ( KODE_ID_CERT_SET == op )
    {
        st = op_cert_set(req, len);
    }
    else if ( (KODE_ID_CERT_GET == op) && (0U == len) )
    {
        st = op_cert_get(out, out_len);
    }
    else if ( KODE_ID_SIGN_AUTH == op )
    {
        st = op_sign_auth(req, len, out, out_len);
    }
    else if ( (KODE_ID_LOCK == op) && (0U == len) )
    {
        st = op_lock();
    }
    else if ( (KODE_ID_STATE == op) && (0U == len) )
    {
        out[0]   = s_flags;
        *out_len = 1U;
        st = KODE_ST_OK;
    }
    else
    {
        st = KODE_ST_BAD_REQUEST;
    }
    return st;
}

void kode_id_init(void)
{
    /* Never erased here, whatever the error: an identity that will not read
     * is reported and left as it is, for a person to look at. */
    esp_err_t const err = nvs_flash_init_partition(KID_PART);
    s_ready = (ESP_OK == err);
    if ( !s_ready )
    {
        ESP_LOGE(TAG, "the identity's partition '%s' will not open (%s); "
                 "it is left as it is and every identity request refused",
                 KID_PART, esp_err_to_name(err));
    }
    flags_refresh();
    kode_svc_register(KODE_SVC_ID, &id_handle);
    ESP_LOGI(TAG, "identity flags 0x%02x (key 0x01, certificate 0x02, locked 0x04)",
             (unsigned)s_flags);
}
