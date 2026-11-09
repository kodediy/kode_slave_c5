/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_hci_filter.h
 * @brief The two HCI commands that carry a BLE key, and the token swap in
 *        them. Plain data, so it runs on the host (test/test_hci_filter.c).
 */
#ifndef KODE_HCI_FILTER_H_
#define KODE_HCI_FILTER_H_

#include <stdbool.h>
#include <stdint.h>

#include "kode_wire.h"

/* ---- A token (the P4's kdrv_ble_tokens.h makes them) --------------------- */
#define KHF_MAGIC_LEN       4U   /**< KODE_TOKEN_LTK or KODE_TOKEN_IRK.        */
#define KHF_KIND_AT         3U   /**< The magic's last letter: 'L' or 'I'.     */
#define KHF_ADDR_AT         4U   /**< The peer's identity address, then type.  */
#define KHF_ADDR_SPAN       7U   /**< Address (6) and its type (1).            */
#define KHF_ROLE_AT         11U  /**< Whose key it is.                         */
#define KHF_ROLE_PEER       1U   /**< The peer's; 0 is ours.                   */

/** @brief Characters of an NVS key name, with its NUL: NVS's longest key. */
#define KHF_NAME_LEN        16U

/** @brief What khf_filter() did to a packet. */
typedef enum {
    KHF_NONE = 0,   /**< No token in it: nothing to do.                        */
    KHF_SWAPPED,    /**< A token was swapped for its key.                      */
    KHF_UNKNOWN     /**< A token nobody knows, left as it is: the controller
                         then fails the encryption, as for a lost key.         */
} khf_result_t;

/**
 * @brief Look a token up.
 * @param token   The token found in the packet, magic first.
 * @param key_out Out: the key, when known.
 * @return true when the token is known.
 */
typedef bool (*khf_lookup_t)(const uint8_t token[KODE_TOKEN_LEN],
                             uint8_t key_out[KODE_BTKEY_LEN]);

/**
 * @brief Swap kodeOS tokens for keys in one host-to-controller HCI packet.
 *
 * Only an LE Long Term Key Request Reply or an LE Add Device To Resolving
 * List with the right parameter length is looked at, and only a field that
 * starts with the token's magic; anything else passes untouched.
 *
 * @param pkt  H4 packet, type byte first.
 * @param len  Bytes.
 * @param look Token lookup.
 * @return What was done.
 */
khf_result_t khf_filter(uint8_t *pkt, uint16_t len, khf_lookup_t look);

/**
 * @brief The NVS key name a token's key is kept under: `l` (an LTK) or `i`
 *        (an IRK), one letter on for the peer's key, then the address and
 *        its type in hex.
 * @param token The token.
 * @param name  Out: the name and its NUL.
 */
void khf_token_name(const uint8_t token[KODE_TOKEN_LEN], char name[KHF_NAME_LEN]);

#endif /* KODE_HCI_FILTER_H_ */
