/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_ethtool.h: Declaration of ethertool related functions. */

#ifndef AQ_ETHTOOL_H
#define AQ_ETHTOOL_H

#include "aq_common.h"

extern const struct ethtool_ops aq_ethtool_ops;
#define AQ_PRIV_FLAGS_MASK   ((AQ_HW_LOOPBACK_MASK) |\
			      (AQ_HW_DOWNSHIFT_MASK) |\
			      (AQ_HW_MEDIA_DETECT_MASK))

struct aq_dump_flag_s {
	union {
		struct {
			u32 ring:5;
			u32 rsvd:27;
		} ring_type;
		struct {
			u32 dump_flag_data:30;
			u32 dump_type:2;
		};
	};
} __packed;

#define AQ_DUMP_TYPE_DESCRIPTOR 0

#endif /* AQ_ETHTOOL_H */
