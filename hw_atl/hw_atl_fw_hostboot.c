// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File hw_atl_fw_hostboot.c
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "../aq_compat.h"
#else
#include <linux/iopoll.h>
#endif
#include <linux/firmware.h>

#include "../aq_hw_utils.h"
#include "../aq_hw.h"
#include "../aq_nic.h"
#include "hw_atl_llh.h"
#include "hw_atl_fw_hostboot.h"
#include "hw_atl_fw_image.h"

#define MAC_IRAM_ADDR	0x1FC00000
#define MAC_DRAM_ADDR	0x1FB00000
#define MAC_BDP_ADDR	0x0
#define MAC_IRAM_SKIP	0x4000
#define MAC_DRAM_SKIP	0xFC00

#define PHY_IRAM_ADDR	0x40000000
#define PHY_DRAM_ADDR	0x3FFE0000
#define PHY_BDP_ADDR	0x0

#define FW_LOADER_PHY_READY                     BIT(0)
#define FW_LOADER_PHY_UPLOAD_FROM_HOST          BIT(9)
#define FW_LOADER_MACBDP_UPLOAD_FROM_HOST       BIT(15)
#define FW_LOADER_PHYBDP_UPLOAD_FROM_HOST       BIT(16)

/*FW loader timeout 1 sec*/
#define FW_LOADER_TIMEOUT			(1000 * 1000)
#define FW_LOADER_STATUS_REG			0x10

#define FW_BDP_FROM_HOST		0x1FB0FC08

#define RBL_MBOX_ADDR_ID		0
#define RBL_MBOX_CMD_ID			1
#define RBL_MBOX_EXEC			0x80000000u
#define RBL_MBOX_LAST_DW_SPEC		0x40000000u
#define RBL_MBOX_COMPLETE		0x55555555u
#define RBL_MBOX_WRONG_ADDRESS		0x66666666u
#define RBL_MBOX_CHUNK_WRITE_DONE	0xAAAAAAAAu
#define RBL_STATUS_ID			2
#define RBL_STATUS_MASK			0xFFFF
#define RBL_STATUS_DONE			0xABBA

#define MAC_MAX_CHUNK 0x20u
#define PHY_MAX_CHUNK 0x10u
#define BDP_MAX_CHUNK 0x10u

static u32 hw_atl_get_mbox_status(struct aq_hw_s *aq_hw)
{
	return hw_atl_reg_glb_cpu_scrpad_nr_get(aq_hw, RBL_MBOX_CMD_ID);
}

static void hw_atl_clear_scratch_pad(struct aq_hw_s *aq_hw, u32 size)
{
	u32 i = 0;

	for (; i < size; ++i)
		hw_atl_reg_glb_cpu_scrpad_set(aq_hw, 0, i);
}

static int hw_atl_upload_data(struct aq_hw_s *aq_hw, u32 addr, const u8 *data,
			      u32 size, u32 max_chunk, bool update_addr,
			      bool mark_last)
{
	u32 offset = 0;

	if (!update_addr)
		hw_atl_reg_glb_cpu_scrpad_nr_set(aq_hw, addr, RBL_MBOX_ADDR_ID);

	while (offset < size) {
		u32 cmd = RBL_MBOX_EXEC;
		u32 chunk_size = 0;
		u32 res = 0;

		if (update_addr)
			hw_atl_reg_glb_cpu_scrpad_nr_set(aq_hw, addr,
							 RBL_MBOX_ADDR_ID);

		for (chunk_size = 0; chunk_size < max_chunk && offset < size;
		     ++chunk_size, offset += sizeof(u32)) {
			u32 val = 0;

			if ((size - offset) >= sizeof(u32)) {
				val = le32_to_cpup((u32 *)(data + offset));
			} else {
				switch (size % offset) {
				case 1:
					val = (u32)(*(data + offset));
					break;
				case 2:
					val = le16_to_cpup((u16 *)(data +
								   offset));
					break;
				case 3:
					val = data[offset] |
					      (data[offset + 1] << 8) |
					      (data[offset + 2] << 16);
					break;
				}
				if (mark_last)
					cmd |= RBL_MBOX_LAST_DW_SPEC;
			}

			hw_atl_reg_glb_cpu_scrpad_set(aq_hw, val, chunk_size);
		}

		cmd |= chunk_size;

		hw_atl_reg_glb_cpu_scrpad_nr_set(aq_hw, cmd, RBL_MBOX_CMD_ID);
		readx_poll_timeout_atomic(hw_atl_get_mbox_status, aq_hw, res,
					  res != cmd, 50, 250 * 1000);
		switch (res) {
		case RBL_MBOX_COMPLETE:
			if ((offset + chunk_size * sizeof(u32)) < size)
				goto err_exit;
			break;
		case RBL_MBOX_WRONG_ADDRESS:
			goto err_exit;
		case RBL_MBOX_CHUNK_WRITE_DONE:
			break;
		default:
			goto err_exit;
		}
		addr += chunk_size * sizeof(u32);
	}

	hw_atl_clear_scratch_pad(aq_hw, max_chunk);
	return 0;

err_exit:
	hw_atl_clear_scratch_pad(aq_hw, max_chunk);
	return -1;
}

static int hw_atl_write_rbl_complete(struct aq_hw_s *aq_hw)
{
	u32 res = 0;

	/* Write data RBL complete*/
	hw_atl_reg_glb_cpu_scrpad_nr_set(aq_hw, RBL_MBOX_EXEC, RBL_MBOX_CMD_ID);
	readx_poll_timeout_atomic(hw_atl_get_mbox_status, aq_hw, res,
				  res != RBL_MBOX_EXEC, 1000, 1000 * 1000);

	switch (res) {
	case RBL_MBOX_COMPLETE:
		break;
	case RBL_MBOX_WRONG_ADDRESS:
		goto err_exit;
	case RBL_MBOX_CHUNK_WRITE_DONE:
		goto err_exit;
	}
	return 0;

err_exit:
	return -1;
}

static u32 hw_atl_get_rbl_status(struct aq_hw_s *aq_hw)
{
	return hw_atl_reg_glb_cpu_scrpad_nr_get(aq_hw, RBL_STATUS_ID);
}

static int hw_atl_wait_for_mac_fw_boot(struct aq_hw_s *aq_hw)
{
	int status = 0;
	int res = 0;

	/* Clear FW Loader status*/
	hw_atl_reg_glb_cpu_scrpad_set(aq_hw, 0x0, FW_LOADER_STATUS_REG);

	status = hw_atl_write_rbl_complete(aq_hw);
	if (status)
		goto exit;

	/* Wait for RBL complete */
	status = readx_poll_timeout_atomic(hw_atl_get_rbl_status, aq_hw, res,
					   (res & RBL_STATUS_MASK) ==
					   RBL_STATUS_DONE,
					   1000, 10 * 1000 * 1000);

	if (status) {
		aq_pr_err("MAC FW load failed: RBL status: %x\n", res);
		goto exit;
	}

	hw_atl_reg_glb_cpu_ctrl2_set(aq_hw, 0xE0);

exit:
	return status;
}

static int hw_atl_mac_fw_load(struct aq_hw_s *aq_hw,
			      struct hw_atl_fw_data *fw_data)
{
	const u8 *data = NULL;
	int status = 0;
	u32 size = 0;

	size = fw_data->mac_iram_size - MAC_IRAM_SKIP;
	data = fw_data->mac_iram + MAC_IRAM_SKIP;

	status = hw_atl_upload_data(aq_hw, MAC_IRAM_ADDR + MAC_IRAM_SKIP,
				    data, size, MAC_MAX_CHUNK, true, false);
	if (status) {
		aq_pr_err("Failed to load MAC IRAM");
		goto exit;
	}

	size = fw_data->mac_dram_size - MAC_DRAM_SKIP;
	data = fw_data->mac_dram + MAC_DRAM_SKIP;

	status = hw_atl_upload_data(aq_hw, MAC_DRAM_ADDR + MAC_DRAM_SKIP,
				    data, size, MAC_MAX_CHUNK, true, false);
	if (status) {
		aq_pr_err("Failed to load MAC DRAM");
		goto exit;
	}

exit:
	return status;
}

static int hw_atl_phy_fw_load(struct aq_hw_s *aq_hw,
			      struct hw_atl_fw_data *fw_data)
{
	int status = 0;

	status = hw_atl_upload_data(aq_hw, PHY_IRAM_ADDR, fw_data->phy_iram,
				    fw_data->phy_iram_size, PHY_MAX_CHUNK,
				    false, false);
	if (status) {
		aq_pr_err("Failed to load PHY IRAM");
		goto exit;
	}

	status = hw_atl_upload_data(aq_hw, PHY_DRAM_ADDR, fw_data->phy_dram,
				    fw_data->phy_dram_size, PHY_MAX_CHUNK,
				    false, false);
	if (status) {
		aq_pr_err("Failed to load PHY DRAM");
		goto exit;
	}

	status = hw_atl_write_rbl_complete(aq_hw);
exit:
	return status;
}

static int hw_atl_bdp_load(struct aq_hw_s *aq_hw, u32 addr, const u8 *data,
			   u32 size)
{
	int status = 0;

	status = hw_atl_upload_data(aq_hw, addr, data, size, BDP_MAX_CHUNK,
				    false, true);
	if (status) {
		aq_pr_err("Failed to load BDP\n");
		goto exit;
	}

	status = hw_atl_write_rbl_complete(aq_hw);

exit:
	return status;
}

int hw_atl_hostboot(struct aq_hw_s *aq_hw)
{
	const struct firmware *fw_image = aq_hw->aq_nic_cfg->fw_image;
	struct hw_atl_fw_data fw_data = {};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	ktime_t timeout = 0;
#else
	ktime_t timeout = {0};
#endif

	int status = 0;
	u32 res = 0;
	u32 tmp = 0;

	if (!fw_image) {
		status = -EINVAL;
		goto err_exit;
	}

	status = hw_atl_fw_image_parse(aq_hw, fw_image, &fw_data);
	if (status)
		goto err_exit;

	status = hw_atl_mac_fw_load(aq_hw, &fw_data);
	if (status)
		goto err_exit;

	if (fw_data.mac_bdp || fw_data.phy_bdp)
		/*Notify FW that BDP will be loaded from host*/
		hw_atl_reg_glb_cpu_scrpad_nr_set(aq_hw, FW_BDP_FROM_HOST,
						 RBL_MBOX_ADDR_ID);

	status = hw_atl_wait_for_mac_fw_boot(aq_hw);
	if (status)
		goto err_exit;

	/*wait for FW_LOADER reports status*/
	timeout = ktime_add_us(ktime_get(), FW_LOADER_TIMEOUT);
	while (true) {
		res = hw_atl_reg_glb_cpu_scrpad_get(aq_hw,
						    FW_LOADER_STATUS_REG);

		if (res & FW_LOADER_PHY_UPLOAD_FROM_HOST & ~tmp) {
			status = hw_atl_phy_fw_load(aq_hw, &fw_data);
			if (status)
				goto err_exit;

			tmp |= FW_LOADER_PHY_UPLOAD_FROM_HOST;
			/* Reset timeout value */
			timeout = ktime_add_us(ktime_get(), FW_LOADER_TIMEOUT);
		}

		if (res & FW_LOADER_MACBDP_UPLOAD_FROM_HOST & ~tmp) {
			status = hw_atl_bdp_load(aq_hw, MAC_BDP_ADDR,
						 fw_data.mac_bdp,
						 fw_data.mac_bdp_size);
			if (status)
				goto err_exit;

			tmp |= FW_LOADER_MACBDP_UPLOAD_FROM_HOST;
			/* Reset timeout value */
			timeout = ktime_add_us(ktime_get(), FW_LOADER_TIMEOUT);
		}

		if (res & FW_LOADER_PHYBDP_UPLOAD_FROM_HOST & ~tmp) {
			status = hw_atl_bdp_load(aq_hw, PHY_BDP_ADDR,
						 fw_data.phy_bdp,
						 fw_data.phy_bdp_size);
			if (status)
				goto err_exit;

			tmp |= FW_LOADER_PHYBDP_UPLOAD_FROM_HOST;
			/* Reset timeout value */
			timeout = ktime_add_us(ktime_get(), FW_LOADER_TIMEOUT);
		}

		if (res & FW_LOADER_PHY_READY)
			break;

		if (ktime_compare(ktime_get(), timeout) > 0) {
			status = -ETIMEDOUT;
			break;
		}
		udelay(100);
	}

	aq_pr_trace("Host load completed successfully");
	return 0;

err_exit:
	return status;
}


