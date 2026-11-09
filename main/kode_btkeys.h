/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_btkeys.h
 * @brief BLE bond keys on the C5 (KODE_SVC_BTKEYS, kode_wire.h): the P4
 *        keeps a token, the controller gets the key.
 */
#ifndef KODE_BTKEYS_H_
#define KODE_BTKEYS_H_

#include <stdint.h>

/** @brief Load the kept keys into RAM and register the service. Before kode_svc_init(). */
void kode_btkeys_init(void);

/**
 * @brief Swap the tokens in one host-to-controller HCI packet for their keys.
 *
 * Runs on the transport's receive path for every packet the host sends the
 * controller, so it reads RAM only - never NVS.
 *
 * @param pkt H4 packet, type byte first.
 * @param len Bytes.
 */
void kode_btkeys_filter(uint8_t *pkt, uint16_t len);

#endif /* KODE_BTKEYS_H_ */
