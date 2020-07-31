/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 * Copyright (C) 2020 Marvell International Ltd.
 */

/* File hw_atl2_.h: Declaration of abstract interface for Atlantic hardware
 * specific functions.
 */

#ifndef HW_ATL2_H
#define HW_ATL2_H

#include "aq_common.h"

#define HW_ATL2_RX_TS_SIZE 8

extern const struct aq_hw_caps_s hw_atl2_caps_aqc113;
extern const struct aq_hw_caps_s hw_atl2_caps_aqc115c;
extern const struct aq_hw_caps_s hw_atl2_caps_aqc116c;
extern const struct aq_hw_ops hw_atl2_ops;

#endif /* HW_ATL2_H */
