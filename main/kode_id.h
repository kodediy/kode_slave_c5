/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_id.h
 * @brief The unit's identity on the C5 (KODE_SVC_ID, kode_wire.h).
 */
#ifndef KODE_ID_H_
#define KODE_ID_H_

/**
 * @brief Read the identity's state from NVS and register the service.
 *        Before kode_svc_init(). Touches no Key Manager key.
 */
void kode_id_init(void);

#endif /* KODE_ID_H_ */
