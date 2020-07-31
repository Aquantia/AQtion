/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File hw_atl_fw_image.h
 */

#ifndef HW_ATL_FW_IMAGE_H
#define HW_ATL_FW_IMAGE_H

#define HW_ATL_MAC_IRAM_MAX_SIZE		0x60000u
#define HW_ATL_MAC_DRAM_MAX_SIZE		0x40000u

struct hw_atl_fw_image_header {
	uint32_t mac_iram_offset;
	uint32_t mac_iram_size;
	uint32_t mac_dram_offset;
	uint32_t mac_dram_size;

	uint32_t phy_iram_offset;
	uint32_t phy_iram_size;
	uint32_t phy_dram_offset;
	uint32_t phy_dram_size;

	uint32_t configuration_offset;
	uint32_t configuration_size;
	uint32_t conf_record_cnt;

	uint32_t mac_crc;
	uint32_t phy_crc;
	uint32_t conf_crc;
} __packed;

struct hw_atl_conf_header {
	uint32_t sub_system_id;
	uint32_t mac_bdp_offset;
	uint32_t mac_bdp_size;
	uint32_t phy_bdp_offset;
	uint32_t phy_bdp_size;
} __packed;

struct hw_atl_fw_data {
	const u8 *mac_iram;
	u32 mac_iram_size;
	const u8 *mac_dram;
	u32 mac_dram_size;

	const u8 *phy_iram;
	u32 phy_iram_size;
	const u8 *phy_dram;
	u32 phy_dram_size;

	const u8 *mac_bdp;
	u32 mac_bdp_size;
	const u8 *phy_bdp;
	u32 phy_bdp_size;
};

int hw_atl_fw_image_parse(struct aq_hw_s *aq_hw,
			  const struct firmware *fw_image,
			  struct hw_atl_fw_data *fw_data);

#endif
