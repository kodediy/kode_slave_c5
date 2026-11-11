/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_sniff.h
 * @brief The Wi-Fi frames service (KODE_SVC_SNIFF): on the host's request the
 *        C5 listens in promiscuous mode on one channel and sends small
 *        batches of frame summaries back (kode_wire.h). Receive only.
 */
#ifndef KODE_SNIFF_H_
#define KODE_SNIFF_H_

#define KODE_SNIFF_PERIOD_MS  100U  /**< One batch at most per period, and only when a frame was heard in it. */
#define KODE_SNIFF_QUEUE_LEN  32U   /**< Records waiting for the task, at most.                              */

/**
 * @brief Register the service's handler. Creates nothing: the record queue,
 *        the lock and the task appear on the first START, and promiscuous
 *        mode is never on before one.
 *
 * Called beside the other services' init functions, before kode_svc_init().
 */
void kode_sniff_init(void);

/**
 * @brief Stop listening: promiscuous mode off, nothing queued, nothing sent
 *        after this returns. Safe when the service never started.
 *
 * Waits for a batch that is being sent to leave. Runs on the kode_svc task:
 * for the STOP request, and for PARK, before its answer.
 */
void kode_sniff_stop(void);

#endif /* KODE_SNIFF_H_ */
