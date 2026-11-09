/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_id_nonce.c
 * @brief The one message the C5 signs with the unit's key: what a nonce may
 *        be, and the exact bytes "kode-auth/v1\n" + nonce.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../main/kode_id_nonce.h"
#include "../main/kode_wire.h"

int main(void)
{
    char n200[201];
    char n201[202];
    uint8_t m[256];

    (void)memset(n200, 'a', 200);
    n200[200] = '\0';
    (void)memset(n201, 'a', 201);
    n201[201] = '\0';

    assert(kode_nonce_ok("aZ09._-", 7U));
    assert(kode_nonce_ok(n200, 200U));
    assert(!kode_nonce_ok(n201, 201U));
    assert(!kode_nonce_ok("", 0U));
    assert(!kode_nonce_ok(NULL, 3U));
    assert(!kode_nonce_ok("a b", 3U));
    assert(!kode_nonce_ok("a\"b", 3U));
    assert(!kode_nonce_ok("a/b", 3U));
    assert(!kode_nonce_ok("a\nb", 3U));
    assert(!kode_nonce_ok("ab\0c", 4U));     /* a NUL inside is not allowed */

    size_t const k = kid_auth_message("abc", 3U, m, sizeof(m));
    assert(16U == k);
    assert(memcmp(m, "kode-auth/v1\nabc", 16U) == 0);
    assert(kid_auth_message(n200, 200U, m, 100U) == 0U);   /* does not fit */

    puts("id nonce: ok");
    return 0;
}
