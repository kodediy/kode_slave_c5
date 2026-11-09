/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_vault.h
 * @brief The Wi-Fi vault on the C5 (KODE_SVC_VAULT, kode_wire.h).
 */
#ifndef KODE_VAULT_H_
#define KODE_VAULT_H_

/** @brief Load the saved networks and register the service. Before kode_svc_init(). */
void kode_vault_init(void);

#endif /* KODE_VAULT_H_ */
