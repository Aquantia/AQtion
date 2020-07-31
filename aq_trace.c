// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2018-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

#include <linux/types.h>
#include <linux/skbuff.h>

#define CREATE_TRACE_POINTS
#include "aq_trace.h"

void trace_aq_tx_descriptor(int ring_idx, unsigned int pointer, u64 descr[2])
{
	switch (DESCR_FIELD(descr[1], 2, 0)) {
	case 1:
		trace_aq_tx_descr(ring_idx, pointer, descr);
	break;
	case 2:
		trace_aq_tx_context_descr(ring_idx, pointer, descr);
	break;
	case 3:
		trace_aq_tx_time_stamp_descr_a2(ring_idx, pointer, descr);
	break;
	}
}
