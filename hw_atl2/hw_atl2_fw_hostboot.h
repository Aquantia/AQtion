/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2021 Marvell International Ltd.
 */

/* File hw_atl2_fw_hostboot.h
 */

#ifndef HW_ATL2_FW_HOSTBOOT_H
#define HW_ATL2_FW_HOSTBOOT_H

typedef enum {
	/* Unknown / wrong RBL / FW data request type */
	HW_ATL2_DATA_REQUEST_UNKNOWN,
	/* RBL or FW image data request type */
	HW_ATL2_DATA_REQUEST_IMAGE,
	/* RBL command data request type */
	HW_ATL2_DATA_REQUEST_CMD,
	/* FW Init-Time Instructions data request type */
	HW_ATL2_DATA_REQUEST_ITI
} hw_atl2_data_req_t;

int hw_atl2_hostboot(struct aq_hw_s *aq_hw);

#endif
