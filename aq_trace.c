/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2018 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
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
	}
}
