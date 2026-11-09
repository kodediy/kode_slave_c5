/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_hci_filter.c
 * @brief The token swap in the two key-carrying HCI commands.
 */
#include <string.h>

#include "kode_hci_filter.h"

#define HCI_H4_COMMAND        0x01U
#define HCI_HDR_LEN           4U       /**< H4 type, opcode (2), plen.         */
#define HCI_OPCODE_LO_AT      1U       /**< Opcode, little-endian: low byte.   */
#define HCI_OPCODE_HI_AT      2U       /**< Opcode: high byte.                 */
#define HCI_PLEN_AT           3U       /**< Parameter length.                  */
#define HCI_LTK_REPLY         0x201AU  /**< LE Long Term Key Request Reply.   */
#define HCI_LTK_REPLY_PLEN    18U      /**< Handle, LTK.                       */
#define HCI_LTK_AT            6U       /**< H4 type, opcode, plen, handle.     */
#define HCI_RL_ADD            0x2027U  /**< LE Add Device To Resolving List.  */
#define HCI_RL_ADD_PLEN       39U      /**< Type, address, peer IRK, local IRK. */
#define HCI_RL_PEER_IRK_AT    11U      /**< H4 type, opcode, plen, type, address. */

/** @brief Swap the token at @p field when it carries @p magic. */
static khf_result_t swap_at(uint8_t *field, const char *magic, khf_lookup_t look)
{
    uint8_t      key[KODE_BTKEY_LEN];
    khf_result_t rc = KHF_NONE;

    if ( memcmp(field, magic, KHF_MAGIC_LEN) == 0 )
    {
        rc = KHF_UNKNOWN;
        if ( (NULL != look) && look(field, key) )
        {
            (void)memcpy(field, key, sizeof(key));
            rc = KHF_SWAPPED;
        }
        (void)memset(key, 0, sizeof(key));
    }
    return rc;
}

khf_result_t khf_filter(uint8_t *pkt, uint16_t len, khf_lookup_t look)
{
    khf_result_t rc = KHF_NONE;

    if ( (NULL != pkt) && (HCI_HDR_LEN <= len) && (HCI_H4_COMMAND == pkt[0]) )
    {
        uint16_t const op = (uint16_t)((uint16_t)pkt[HCI_OPCODE_LO_AT]
                                       | ((uint16_t)pkt[HCI_OPCODE_HI_AT] << 8));
        uint8_t const  pl = pkt[HCI_PLEN_AT];

        if ( (HCI_LTK_REPLY == op) && (HCI_LTK_REPLY_PLEN == pl)
            && ((HCI_HDR_LEN + HCI_LTK_REPLY_PLEN) <= len) )
        {
            rc = swap_at(&pkt[HCI_LTK_AT], KODE_TOKEN_LTK, look);
        }
        else if ( (HCI_RL_ADD == op) && (HCI_RL_ADD_PLEN == pl)
                 && ((HCI_HDR_LEN + HCI_RL_ADD_PLEN) <= len) )
        {
            rc = swap_at(&pkt[HCI_RL_PEER_IRK_AT], KODE_TOKEN_IRK, look);
        }
        else
        {
            rc = KHF_NONE;
        }
    }
    return rc;
}

void khf_token_name(const uint8_t token[KODE_TOKEN_LEN], char name[KHF_NAME_LEN])
{
    static const char HEX[] = "0123456789abcdef";

    name[0] = 'l';
    if ( (uint8_t)'I' == token[KHF_KIND_AT] )
    {
        name[0] = 'i';
    }
    if ( KHF_ROLE_PEER == token[KHF_ROLE_AT] )
    {
        name[0] = (char)(name[0] + 1);   /* the peer's: 'm', 'j' */
    }
    for ( size_t i = 0U; KHF_ADDR_SPAN > i; i++ )
    {
        name[1U + (2U * i)] = HEX[token[KHF_ADDR_AT + i] >> 4];
        name[2U + (2U * i)] = HEX[token[KHF_ADDR_AT + i] & 0x0FU];
    }
    name[KHF_NAME_LEN - 1U] = '\0';
}
