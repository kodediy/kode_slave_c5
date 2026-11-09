/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_btkeys_cache.h
 * @brief The table of BLE bond keys the C5 keeps in RAM, by token. Plain
 *        data with no lock of its own (kode_btkeys.c holds one), so it runs
 *        on the host (test/test_btkeys_cache.c).
 */#ifndef KODE_BTKEYS_CACHE_H_
#define KODE_BTKEYS_CACHE_H_

#include <stdbool.h>
#include <stdint.h>

#include "kode_wire.h"

/** @brief Slots: three bonds on the P4, each with our LTK, the peer's LTK and the peer's IRK. */
#define KBC_SLOTS  12U

/** @brief One token and the key behind it. */
typedef struct {
    uint8_t token[KODE_TOKEN_LEN];   /**< What the P4 holds in the key's place. */
    uint8_t key[KODE_BTKEY_LEN];     /**< What the controller needs.            */
    bool    used;                    /**< The slot holds a pair.                */
} kbc_slot_t;

/** @brief The table; all zero is empty. */
typedef struct {
    kbc_slot_t slot[KBC_SLOTS];   /**< The pairs, in no order.                  */
} kbc_t;

/**
 * @brief Whether 16 bytes are a token.
 * @param t KODE_TOKEN_LEN bytes.
 * @return true when an LTK's or an IRK's magic comes first.
 */
bool kbc_is_token(const uint8_t *t);

/**
 * @brief Put a token and its key in the table, replacing the same token.
 * @param c     The table.
 * @param token KODE_TOKEN_LEN bytes, checked with kbc_is_token() by the caller.
 * @param key   KODE_BTKEY_LEN bytes.
 * @return false when every slot holds another token (nothing changes).
 */
bool kbc_put(kbc_t *c, const uint8_t *token, const uint8_t *key);

/**
 * @brief Drop a token, zeroing its slot.
 * @param c     The table.
 * @param token KODE_TOKEN_LEN bytes; nothing happens when absent.
 */
void kbc_del(kbc_t *c, const uint8_t *token);

/**
 * @brief Find the key behind a token.
 * @param c       The table.
 * @param token   KODE_TOKEN_LEN bytes.
 * @param key_out Out: KODE_BTKEY_LEN bytes, written only when found.
 * @return true when the token is known.
 */
bool kbc_lookup(const kbc_t *c, const uint8_t *token, uint8_t *key_out);

/**
 * @brief Slots in use.
 * @param c The table.
 * @return How many tokens it holds.
 */
uint8_t kbc_count(const kbc_t *c);

/**
 * @brief Forget every pair, zeroing the table.
 * @param c The table.
 */
void kbc_clear(kbc_t *c);

#endif /* KODE_BTKEYS_CACHE_H_ */
