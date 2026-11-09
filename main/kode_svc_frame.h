/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_svc_frame.h
 * @brief What a request frame must look like before the dispatcher serves
 *        it, and the policy that keeps an updated image once. Plain data, so
 *        it runs on the host (test/test_svc_frame.c).
 */#ifndef KODE_SVC_FRAME_H_
#define KODE_SVC_FRAME_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kode_wire.h"

/** @brief What a request frame turned out to be. */
typedef enum {
    KSF_OK = 0,        /**< Readable: this wire version, length as declared.   */
    KSF_TOO_SHORT,     /**< Shorter than a header: there is nobody to answer.  */
    KSF_BAD_VERSION,   /**< Another wire version: answered BAD_REQUEST anyway. */
    KSF_BAD_LENGTH     /**< The header's length is not what arrived.           */
} ksf_verdict_t;

/** @brief Whether the image has been kept yet; zero-initialised is "not yet". */
typedef struct {
    bool done;   /**< Set by the first well-formed request.                   */
} ksf_confirm_t;

/**
 * @brief Judge one request frame.
 * @param msg The whole frame, header first.
 * @param len Its bytes.
 * @param h   Out: the header, filled whenever the frame holds one (every
 *            verdict but KSF_TOO_SHORT), so an answer can echo it.
 * @return The verdict. The version is judged before the length.
 */
ksf_verdict_t ksf_check(const uint8_t *msg, size_t len, kode_hdr_t *h);

/**
 * @brief Whether a request is one the receive thread may queue.
 * @param data The frame as it arrived.
 * @param len  Its bytes.
 * @return true when there is data and it holds a header and at most
 *         KODE_MAX_PAYLOAD bytes after it.
 */
bool ksf_request_fits(const void *data, size_t len);

/**
 * @brief Whether this request is the one that confirms the running image.
 *
 * Only a request this image can read proves the host speaks to it, so a
 * frame that is not well-formed never confirms; and once is enough.
 *
 * @param st    The policy's state, updated.
 * @param valid true when ksf_check() said KSF_OK.
 * @return true exactly once: on the first valid request.
 */
bool ksf_should_confirm(ksf_confirm_t *st, bool valid);

#endif /* KODE_SVC_FRAME_H_ */
