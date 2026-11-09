/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_vault_list.h
 * @brief The vault's list of networks, most recently used first, as plain
 *        data: no NVS, no Wi-Fi, so it runs on the host
 *        (test/test_vault_list.c).
 */
#ifndef KODE_VAULT_LIST_H_
#define KODE_VAULT_LIST_H_

#include <stdbool.h>
#include <stdint.h>

#include "kode_wire.h"

/** @brief Shortest WPA passphrase; a longer one up to KODE_PASS_MAX, or none. */
#define KV_PASS_MIN  8U

/** @brief kv_find()'s answer when the network is not in the list. */
#define KV_ABSENT    (-1)

/** @brief One network. */
typedef struct {
    char ssid[KODE_SSID_MAX + 1U];   /**< 1..32 bytes and a NUL.            */
    char pass[KODE_PASS_MAX + 1U];   /**< Empty, or 8..64 bytes, and a NUL. */
} kv_entry_t;

/** @brief The list, most recently used first. */
typedef struct {
    uint8_t    count;                     /**< Entries used.                */
    kv_entry_t e[KODE_VAULT_NETS_MAX];    /**< e[0] is the most recent.     */
} kv_list_t;

/**
 * @brief Whether a credential is one Wi-Fi accepts.
 * @param ssid 1..32 bytes.
 * @param pass Empty (open), or 8..64 bytes (WPA passphrase or hex PSK).
 * @return true when both are in range.
 */
bool kv_valid(const char *ssid, const char *pass);

/**
 * @brief Add or refresh a network at the front; the oldest goes when the
 *        list holds KODE_VAULT_NETS_MAX.
 * @param l    The list.
 * @param ssid Checked by the caller with kv_valid().
 * @param pass Likewise.
 */
void kv_remember(kv_list_t *l, const char *ssid, const char *pass);

/**
 * @brief Where a network is in the list.
 * @param l    The list.
 * @param ssid Its name.
 * @return Its index, or KV_ABSENT.
 */
int8_t kv_find(const kv_list_t *l, const char *ssid);

/**
 * @brief Move a network to the front, keeping its password.
 * @param l    The list.
 * @param ssid Its name; nothing happens when absent.
 */
void kv_touch(kv_list_t *l, const char *ssid);

/**
 * @brief Remove a network, wiping its password.
 * @param l    The list.
 * @param ssid Its name.
 * @return true when it was there.
 */
bool kv_forget(kv_list_t *l, const char *ssid);

#endif /* KODE_VAULT_LIST_H_ */
