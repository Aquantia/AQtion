// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2021 Marvell International Ltd.
 */

/* File hw_atl2_fw_hostboot.c
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
#include "hw_atl/hw_atl_llh.h"
#include "hw_atl2_fw_hostboot.h"
#include "hw_atl2_llh.h"
#include "hw_atl2_llh_internal.h"

#define HW_ATL2_MAX_IMAGE_OFFSET 0x80000
#define HW_ATL2_MAX_IMAGE_LENGTH 0x1000
#define HW_ATL2_FW_LOADER_REQ_OFFSET_REG 0x0328
#define HW_ATL2_FW_LOADER_REQ_LENGTH_REG 0x032C
#define HW_ATL2_RBL_CMD_DATA_REQUEST_MASK 0x80000000
#define HW_ATL2_FW_ITI_DATA_REQUEST_MASK 0x00100000
#define HW_ATL2_MAC_HOSTBOOT_TIMEOUT_US 10000000
#define HW_ATL2_FIRMWARE_DONE_TIMEOUT_US 3000000
#define HW_ATL2_RBL_HOSTBOOT_TIMEOUT_US 10000000

static void hw_atl2_upload_data(struct aq_hw_s *aq_hw, u32 addr, u32 size, const u8 *buffer)
{
	u32 index, cur_addr, dword_size, bytes_pending, val;
	u8 *data = (u8 *)buffer;
	int i;

	index = 0;
	if (addr & 0x3) {
		cur_addr = rounddown(addr, 4);
		val = aq_hw_read_reg(aq_hw, cur_addr);

		for (i = addr & 0x3; (i < 4) && (index < size); i++) {
			switch (i) {
			case 1:
				val = (val & 0xFFFF00FF) | ((u32)data[index++] << 8);
				break;
			case 2:
				val = (val & 0xFF00FFFF) | ((u32)data[index++] << 16);
				break;
			case 3:
				val = (val & 0x00FFFFFF) | ((u32)data[index++] << 24);
				break;
			default:
				break;
			}
		}

		aq_hw_write_reg(aq_hw, cur_addr, val);
	}

	dword_size = (size - index) / 4;
	bytes_pending = (size - index) % 4;

	for (i = 0; i < dword_size; i++) {
		val = *(u32 *)&data[index];
		aq_hw_write_reg(aq_hw, addr + index, val);
		index += 4;
	}

	if (bytes_pending) {
		cur_addr = addr + index;
		val = aq_hw_read_reg(aq_hw, cur_addr);

		switch (bytes_pending) {
		case 1:
			val = (val & 0xFFFFFF00) | ((u32)data[index]);
			break;
		case 2:
			val = (val & 0xFFFF0000) | ((u32)data[index + 1] << 8) | ((u32)data[index]);
			break;
		case 3:
			val = (val & 0xFF000000) | ((u32)data[index + 2] << 16) |
			((u32)data[index + 1] << 8) | ((u32)data[index]);
			break;
		default:
			break;
		}

		aq_hw_write_reg(aq_hw, cur_addr, val);
	}
}

static int hw_atl2_image_load(struct aq_hw_s *aq_hw, const u8 *data, u32 size, u32 offset,
			      u32 length, hw_atl2_data_req_t req)
{
	u32 off, len;

	off = offset & (HW_ATL2_MAX_IMAGE_OFFSET - 1);
	len = length & (HW_ATL2_MAX_IMAGE_LENGTH - 1);

	/* Check that start of fragment is present in provided data */
	if (off * 4 >= size) {
		if (req == HW_ATL2_DATA_REQUEST_CMD)
			aq_pr_err("Requested fragment (0x%x:0x%x) is beyond command data\n",
				  offset, offset + length);
		else if (req == HW_ATL2_DATA_REQUEST_ITI)
			aq_pr_err("Requested fragment (0x%x:0x%x) is beyond Init-Time Instr data\n",
				  offset, offset + length);
		else
			aq_pr_err("Requested fragment (0x%x:0x%x) is beyond image data\n",
				  offset, offset + length);
		return -EINVAL;
	}

	/* Allow actual data size to be less that requested data size */
	len = min((size - off * 4) / 4, len);

	/* Confirm data request: clear interrupt */
	aq_hw_write_reg(aq_hw, HW_ATL2_CLEAR_HOST_IRQ_REG, HW_ATL2_HOST_IRQ_MASK);

	/* Needed for FW data requests: fill struct in shared buffer */
	if (req == HW_ATL2_DATA_REQUEST_IMAGE || req == HW_ATL2_DATA_REQUEST_ITI)
		hw_atl2_utils_set_db_status(aq_hw, offset, length);

	/* Fill shared buffer with data and confirm it is ready */
	hw_atl2_upload_data(aq_hw, HW_ATL2_SHMEM_BUF_MMIO_ADDR, len * 4, data + off * 4);

	aq_hw_write_reg(aq_hw, HW_ATL2_CONFIRM_SHARED_BUF_REG, HW_ATL2_CONFIRM_SHARED_BUF_MASK);

	return 0;
}

static hw_atl2_data_req_t hw_atl2_get_data_req_type(u32 offset, u32 length)
{
	if (offset < HW_ATL2_MAX_IMAGE_OFFSET && length <= HW_ATL2_MAX_IMAGE_LENGTH)
		return HW_ATL2_DATA_REQUEST_IMAGE;
	else if ((offset & HW_ATL2_RBL_CMD_DATA_REQUEST_MASK) != 0 &&
		  offset < (HW_ATL2_RBL_CMD_DATA_REQUEST_MASK | HW_ATL2_MAX_IMAGE_OFFSET) &&
		  length <= HW_ATL2_MAX_IMAGE_LENGTH)
		return HW_ATL2_DATA_REQUEST_CMD;
	else if ((offset & HW_ATL2_FW_ITI_DATA_REQUEST_MASK) != 0 &&
		  offset < (HW_ATL2_FW_ITI_DATA_REQUEST_MASK | HW_ATL2_MAX_IMAGE_OFFSET) &&
		  length <= HW_ATL2_MAX_IMAGE_LENGTH)
		return HW_ATL2_DATA_REQUEST_ITI;

	aq_pr_trace("Unrecognized RBL/FW data request. Offset: 0x%x, Length: 0x%x\n", offset, length);

	return HW_ATL2_DATA_REQUEST_UNKNOWN;
}

static bool hw_atl2_is_fw_booted(struct aq_hw_s *aq_hw)
{
	return !!(hw_atl2_mif_mcp_boot_reg_get(aq_hw) & AQ_A2_HOST_DATA_LOADED);
}

static int hw_atl2_await_mac_phy_load(struct aq_hw_s *aq_hw, const u8 *image, u32 image_size)
{
	struct version_s version;
	hw_atl2_data_req_t req;
	u32 offset, length;
	int ret;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	ktime_t timeout = 0;
#else
	ktime_t timeout = {0};
#endif

	hw_atl2_utils_get_version(aq_hw, &version);
	aq_pr_trace("Loaded MAC FW Version: %u.%u.%u\n", version.mac.major, version.mac.minor,
		    version.mac.build);

	if (!hw_atl2_is_fw_booted(aq_hw))
		aq_pr_trace("Waiting for MAC FW to complete boot and start PHY FW...\n");

	/* wait for FW_LOADER reports status */
	timeout = ktime_add_us(ktime_get(), HW_ATL2_MAC_HOSTBOOT_TIMEOUT_US);
	while (ktime_compare(ktime_get(), timeout) <= 0) {
		if (hw_atl2_is_fw_booted(aq_hw))
			break;

		/* Check FW data request */
		if (hw_atl2_mif_host_req_int_get(aq_hw) & HW_ATL2_MCP_HOST_REQ_INT_READY) {
			/* Read request parameters */
			offset = aq_hw_read_reg(aq_hw, HW_ATL2_FW_LOADER_REQ_OFFSET_REG);
			length = aq_hw_read_reg(aq_hw, HW_ATL2_FW_LOADER_REQ_LENGTH_REG);

			req = hw_atl2_get_data_req_type(offset, length);
			if (req != HW_ATL2_DATA_REQUEST_IMAGE) {
				aq_pr_trace("Request type is unknown or not hanlded by the driver");
				return -EINVAL;
			}

			ret = hw_atl2_image_load(aq_hw, image, image_size, offset, length, req);
			if (ret)
				return ret;
		}
		mdelay(10);
	}

	if (!hw_atl2_is_fw_booted(aq_hw)) {
		aq_pr_trace("Error: Timeout waiting for MAC FW to finish boot\n");
		return -ETIMEDOUT;
	}

	/* Report PHY FW version (from MAC FW shared buffer) and bundle version */
	hw_atl2_utils_get_version(aq_hw, &version);
	aq_pr_trace("Loaded PHY FW Version: %u.%u.%u (reported by MAC FW)\n", version.phy.major,
		    version.phy.minor, version.phy.build);
	aq_pr_trace("Loaded bundle: %u.%u.%u\n", version.bundle.major, version.bundle.minor,
		    version.bundle.build);

	return 0;
}

int hw_atl2_hostboot(struct aq_hw_s *aq_hw)
{
	const struct firmware *fw_image = aq_hw->aq_nic_cfg->fw_image;
	u32 offset, length, irq_status, rbl_status;
	hw_atl2_data_req_t req;
	int status = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
	ktime_t timeout = 0;
#else
	ktime_t timeout = {0};
#endif

	if (!fw_image) {
		status = -EINVAL;
		goto err_exit;
	}

	timeout = ktime_add_us(ktime_get(), HW_ATL2_FIRMWARE_DONE_TIMEOUT_US +
			       HW_ATL2_RBL_HOSTBOOT_TIMEOUT_US);
	while (ktime_compare(ktime_get(), timeout) <= 0) {
		irq_status = hw_atl2_mif_host_req_int_get(aq_hw);

		rbl_status = hw_atl2_mif_mcp_boot_reg_get(aq_hw);

		if (rbl_status & AQ_A2_FW_INIT_COMP_SUCCESS) {
			aq_pr_err("Chip reset completed rbl_status = 0x%x", rbl_status);
			break;
		}

		if (irq_status & HW_ATL2_MCP_HOST_REQ_INT_READY) {
			offset = aq_hw_read_reg(aq_hw, HW_ATL2_FW_LOADER_REQ_OFFSET_REG);
			length = aq_hw_read_reg(aq_hw, HW_ATL2_FW_LOADER_REQ_LENGTH_REG);

			/* Get current data request type and validate */
			req = hw_atl2_get_data_req_type(offset, length);
			if (req != HW_ATL2_DATA_REQUEST_IMAGE) {
				status = -EINVAL;
				aq_pr_trace("Request type is unknown or not hanlded by the driver");
				goto err_exit;
			}

			status = hw_atl2_image_load(aq_hw, fw_image->data, fw_image->size, offset, length, req);
			if (status)
				goto err_exit;
		}
		mdelay(10);
	}

	/* Wait for MAC FW to complete boot and load PHY FW */
        status = hw_atl2_await_mac_phy_load(aq_hw, fw_image->data, fw_image->size);
	if (status)
		goto err_exit;

	aq_pr_trace("Host load completed successfully");

	return 0;
err_exit:
	return status;
}
