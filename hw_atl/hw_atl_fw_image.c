// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File hw_atl_fw_image.c
 */
#include <linux/firmware.h>
#include <linux/crc-itu-t.h>

#include "../aq_hw_utils.h"
#include "../aq_hw.h"
#include "../aq_nic.h"
#include "hw_atl_fw_image.h"



int hw_atl_fw_image_parse(struct aq_hw_s *aq_hw,
			  const struct firmware *fw_image,
			  struct hw_atl_fw_data *fd)
{
	const struct hw_atl_fw_image_header *h = NULL;
	const struct hw_atl_conf_header *ch = NULL;
	u32 ssid = aq_hw->ssid;
	const u8 *data = NULL;
	size_t data_size = 0;
	u32 conf_cnt = 0;
	u32 offset = 0;
	u32 size = 0;
	u16 crc = 0;
	u32 i = 0;

	if (!fw_image) {
		pr_err("No FW image loaded\n");
		goto err_exit;
	}

	if (!fd)
		goto err_exit;

	data = fw_image->data;
	data_size = fw_image->size;

	if (data_size < sizeof(struct hw_atl_fw_image_header)) {
		aq_pr_err("Incorrect size: data_size: %zx, header size: %zx\n",
			  data_size, sizeof(struct hw_atl_fw_image_header));
		goto err_exit;
	}

	h = (struct hw_atl_fw_image_header *)data;

	/*MAC*/
	size = le32_to_cpu(h->mac_iram_size);
	offset = le32_to_cpu(h->mac_iram_offset);
	if (!size) {
		aq_pr_err("MAC IRAM size should not be zero\n");
		goto err_exit;
	}
	if (size > HW_ATL_MAC_IRAM_MAX_SIZE) {
		aq_pr_err("MAC IRAM size to high: %x\n", size);
		goto err_exit;
	}
	if (data_size < offset) {
		aq_pr_err("Incorrect size: data_size: %zx, "
			  "mac_iram_offset: %x\n", data_size, offset);
		goto err_exit;
	}
	if (data_size < offset + size) {
		aq_pr_err("Incorrect size: data_size: %zx, mac_iram_end: %x\n",
			  data_size, offset + size);
		goto err_exit;
	}

	fd->mac_iram = data + offset;
	fd->mac_iram_size = size;
	crc = crc_itu_t(0, fd->mac_iram, fd->mac_iram_size);

	size = le32_to_cpu(h->mac_dram_size);
	offset = le32_to_cpu(h->mac_dram_offset);

	if (!size) {
		aq_pr_err("MAC DRAM size should not be zero\n");
		goto err_exit;
	}
	if (size > HW_ATL_MAC_DRAM_MAX_SIZE) {
		aq_pr_err("MAC DRAM size to high: %x\n", size);
		goto err_exit;
	}
	if (data_size < h->mac_dram_offset) {
		aq_pr_err("Incorrect size: data_size: %zx, "
			  "mac_dram_offset: %x\n", data_size, offset);
		goto err_exit;
	}
	if (data_size < offset + size) {
		aq_pr_err("Incorrect size: data_size: %zx, mac_dram_end: %x\n",
			  data_size, offset + size);
		goto err_exit;
	}

	fd->mac_dram = data + offset;
	fd->mac_dram_size = size;
	crc = crc_itu_t(crc, fd->mac_dram, fd->mac_dram_size);

	if (crc != le32_to_cpu(h->mac_crc)) {
		aq_pr_err("MAC CRC incorrect: calculated: %x, from image: %x\n",
			  crc, le32_to_cpu(h->mac_crc));
		goto err_exit;
	}

	/*PHY*/
	size = le32_to_cpu(h->phy_iram_size);
	offset = le32_to_cpu(h->phy_iram_offset);

	if (!size) {
		aq_pr_err("PHY IRAM size should not be zero\n");
		goto err_exit;
	}
	if (data_size < offset) {
		aq_pr_err("Incorrect size: data_size: %zx, "
			  "phy_iram_offset: %x\n", data_size, offset);
		goto err_exit;
	}
	if (data_size < offset + size) {
		aq_pr_err("Incorrect size: data_size: %zx, phy_iram_end: %x\n",
			  data_size, offset + size);
		goto err_exit;
	}

	fd->phy_iram = data + offset;
	fd->phy_iram_size = size;
	crc = crc_itu_t(0, fd->phy_iram, fd->phy_iram_size);

	size = le32_to_cpu(h->phy_dram_size);
	offset = le32_to_cpu(h->phy_dram_offset);

	if (!size) {
		aq_pr_err("PHY DRAM size should not be zero\n");
		goto err_exit;
	}
	if (data_size < offset) {
		aq_pr_err("Incorrect size: data_size: %zx, "
			  "phy_dram_offset: %x\n", data_size, offset);
		goto err_exit;
	}
	if (data_size < offset + size) {
		aq_pr_err("Incorrect size: data_size: %zx, phy_dram_end: %x\n",
			  data_size, offset + size);
		goto err_exit;
	}

	fd->phy_dram = data + offset;
	fd->phy_dram_size = size;
	crc = crc_itu_t(crc, fd->phy_dram, fd->phy_dram_size);

	if (crc != le32_to_cpu(h->phy_crc)) {
		aq_pr_err("PHY CRC incorrect: calculated: %x, from image: %x\n",
			  crc, le32_to_cpu(h->phy_crc));
		goto err_exit;
	}

	/*configuration*/
	offset = le32_to_cpu(h->configuration_offset);
	conf_cnt = le32_to_cpu(h->conf_record_cnt);
	if (data_size < offset) {
		aq_pr_err("Incorrect size: data_size: %zx, conf_offset: %x\n",
			  data_size, offset);
		goto err_exit;
	}

	if (data_size <
	    offset + conf_cnt * sizeof(struct hw_atl_conf_header)) {
		aq_pr_err("Incorrect size: data_size: %zx, conf_end: %zx\n",
			  data_size, offset + conf_cnt *
			  sizeof(struct hw_atl_conf_header));
		goto err_exit;
	}

	ch = (struct hw_atl_conf_header *)(data + offset);
	crc = 0;

	if (aq_hw->aq_nic_cfg->fw_sid)
		ssid = aq_hw->aq_nic_cfg->fw_sid;

	for (i = 0; i < h->conf_record_cnt; ++i) {
		u32 ssid_cur = le32_to_cpu(ch->sub_system_id);

		crc = crc_itu_t(crc, (u8 *)ch,
				sizeof(struct hw_atl_conf_header));
		offset = le32_to_cpu(ch->mac_bdp_offset);
		size = le32_to_cpu(ch->mac_bdp_size);
		if (data_size < offset) {
			aq_pr_err("Incorrect size: data_size: %zx, "
				  "mac_bdp_offset: %x\n",
				  data_size, offset);
			goto err_exit;
		}
		if (data_size < offset + size) {
			aq_pr_err("Incorrect size: data_size: %zx, "
				  "mac_bdp_end: %x\n", data_size,
				  offset + size);
			goto err_exit;
		}
		crc = crc_itu_t(crc, data + offset, size);

		if (ssid == ssid_cur) {
			fd->mac_bdp = data + offset;
			fd->mac_bdp_size = size;
		}

		offset = le32_to_cpu(ch->phy_bdp_offset);
		size = le32_to_cpu(ch->phy_bdp_size);
		if (data_size < offset) {
			aq_pr_err("Incorrect size: data_size: %zx, "
				  "phy_bdp_offset: %x\n", data_size, offset);
			goto err_exit;
		}
		if (data_size < offset + size) {
			aq_pr_err("Incorrect size: data_size: %zx, "
				  "phy_bdp_end: %x\n", data_size,
				  offset + size);
			goto err_exit;
		}

		crc = crc_itu_t(crc, data + offset, size);

		if (ssid == ssid_cur) {
			fd->phy_bdp = data + offset;
			fd->phy_bdp_size = size;
		}
		++ch;
	}

	if (crc != le32_to_cpu(h->conf_crc)) {
		aq_pr_err("Conf CRC incorrect: calculated: %x, "
			  "from image: %x\n", crc, le32_to_cpu(h->conf_crc));
		goto err_exit;
	}

	return 0;

err_exit:
	return -1;
}


