/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File hw_atl_a0.h: Declaration of abstract interface for Atlantic hardware
 * specific functions.
 */

#ifndef HW_ATL_A0_H
#define HW_ATL_A0_H

#include "../aq_common.h"

extern const struct aq_hw_caps_s hw_atl_a0_caps_aqc100;
extern const struct aq_hw_caps_s hw_atl_a0_caps_aqc107;
extern const struct aq_hw_caps_s hw_atl_a0_caps_aqc108;
extern const struct aq_hw_caps_s hw_atl_a0_caps_aqc109;

extern const struct aq_hw_ops hw_atl_ops_a0;

#endif /* HW_ATL_A0_H */
