/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_sniff_rec.h
 * @brief One Wi-Fi frame heard, as the record the wire carries: its kind, the
 *        length of its MAC header and the record built from the frame. Plain
 *        data, no ESP-IDF, so it runs on the host (test/test_sniff_rec.c).
 */
#ifndef KODE_SNIFF_REC_H_
#define KODE_SNIFF_REC_H_

#include <stdbool.h>
#include <stdint.h>

#include "kode_wire.h"

/* ---- Frame control (IEEE 802.11) ------------------------------------------ */
#define KSR_FC_LEN          2U     /**< Bytes of frame control.                */
#define KSR_TYPE_SHIFT      2U     /**< Type: bits 2-3 of byte 0.              */
#define KSR_TYPE_MASK       0x03U  /**< The type's width, once shifted.        */
#define KSR_QOS_BIT         0x80U  /**< Byte 0: a data subtype with QoS.       */
#define KSR_TODS_BIT        0x01U  /**< Byte 1: to the distribution system.    */
#define KSR_FROMDS_BIT      0x02U  /**< Byte 1: from the distribution system.  */

/* ---- Frame layout ---------------------------------------------------------- */
#define KSR_ADDR_LEN        6U     /**< Bytes of one MAC address.              */
#define KSR_ADDR1_AT        4U     /**< Address 1 starts here.                 */
#define KSR_ADDR2_AT        10U    /**< Address 2 starts here.                 */
#define KSR_MIN_LEN         10U    /**< Shortest frame: an ACK, address 1 only. */
#define KSR_ADDR2_MIN_LEN   16U    /**< A frame this long has an address 2.    */
#define KSR_HDR_LEN         24U    /**< MAC header with three addresses.       */
#define KSR_QOS_LEN         2U     /**< The QoS control field of a QoS data frame. */
#define KSR_ADDR4_LEN       6U     /**< The fourth address, when ToDS and FromDS. */

/** @brief Frame kinds, from frame control's type bits. */
typedef enum {
    KSR_MGMT  = 0,   /**< Management: beacons, probes, authentication.        */
    KSR_CTRL  = 1,   /**< Control: ACK, RTS, CTS.                             */
    KSR_DATA  = 2,   /**< Data, QoS or not.                                   */
    KSR_OTHER = 3    /**< The reserved type.                                  */
} ksr_kind_t;

/**
 * @brief The kind of a frame.
 * @param fc The frame's first two bytes, frame control as on the air.
 * @return The kind its type bits name.
 */
ksr_kind_t ksr_kind(const uint8_t fc[KSR_FC_LEN]);

/**
 * @brief Bytes of the MAC header of a frame with this frame control.
 * @param fc The frame's first two bytes.
 * @return 24; 26 for QoS data; 30 or 32 for a data frame with four addresses
 *         (both ToDS and FromDS set), without or with QoS.
 */
uint8_t ksr_header_len(const uint8_t fc[KSR_FC_LEN]);

/**
 * @brief Fill a record from a frame: frame control, both addresses, the
 *        length on the air and the first KODE_SNIFF_HEAD_LEN bytes after the
 *        MAC header, zeros past the end of the frame.
 * @param frame The frame as the radio handed it over, without the FCS.
 * @param len   Its length on the air.
 * @param rssi  The signal level it was heard at, dBm.
 * @param out   Out: the record; left as it was when this returns false.
 * @return false for a frame shorter than KSR_MIN_LEN, or a NULL argument.
 */
bool ksr_build(const uint8_t *frame, uint16_t len, int8_t rssi, kode_sniff_rec_t *out);

#endif /* KODE_SNIFF_REC_H_ */
