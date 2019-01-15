/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File hw_atl_utils_fw2x.c: Definition of firmware 2.x functions for
 * Atlantic hardware abstraction layer.
 */

#include "../aq_hw.h"
#include "../aq_hw_utils.h"
#include "../aq_pci_func.h"
#include "../aq_ring.h"
#include "../aq_vec.h"
#include "../aq_nic.h"
#include "hw_atl_utils.h"
#include "hw_atl_llh.h"

#define HW_ATL_FW2X_MPI_EFUSE_ADDR       0x364
#define HW_ATL_FW2X_MPI_MBOX_ADDR        0x360
#define HW_ATL_FW2X_MPI_RPC_ADDR         0x334

#define HW_ATL_FW2X_MPI_CONTROL_ADDR     0x368
#define HW_ATL_FW2X_MPI_CONTROL2_ADDR    0x36C
#define HW_ATL_FW2X_MPI_LED_ADDR         0x31c

#define HW_ATL_FW2X_MPI_STATE_ADDR       0x370
#define HW_ATL_FW2X_MPI_STATE2_ADDR      0x374
#define HW_ATL_FW2X_MPI_CONTROL3_ADDR    0x374

#define HW_ATL_FW3X_EXT_CONTROL_ADDR	 0x378
#define HW_ATL_FW3X_EXT_STATE_ADDR		 0x37c

#define HW_ATL_FW2X_CAP_SLEEP_PROXY      BIT(CAPS_HI_SLEEP_PROXY)
#define HW_ATL_FW2X_CAP_WOL              BIT(CAPS_HI_WOL)

#define HW_ATL_FW2X_CTRL_SLEEP_PROXY      BIT(CTRL_SLEEP_PROXY)
#define HW_ATL_FW2X_CTRL_WOL              BIT(CTRL_WOL)
#define HW_ATL_FW2X_CTRL_LINK_DROP        BIT(CTRL_LINK_DROP)
#define HW_ATL_FW2X_CTRL_TEMPERATURE      BIT(CTRL_TEMPERATURE)
#define HW_ATL_FW2X_CTRL_STATISTICS       BIT(CTRL_STATISTICS)
#define HW_ATL_FW2X_CTRL_PAUSE            BIT(CTRL_PAUSE)
#define HW_ATL_FW2X_CTRL_ASYMMETRIC_PAUSE BIT(CTRL_ASYMMETRIC_PAUSE)
#define HW_ATL_FW2X_CTRL_INT_LOOPBACK     BIT(CTRL_INT_LOOPBACK)
#define HW_ATL_FW2X_CTRL_EXT_LOOPBACK     BIT(CTRL_EXT_LOOPBACK)
#define HW_ATL_FW2X_CTRL_FORCE_RECONNECT  BIT(CTRL_FORCE_RECONNECT)

#define HW_ATL_FW2X_CAP_EEE_1G_MASK      BIT(CAPS_HI_1000BASET_FD_EEE)
#define HW_ATL_FW2X_CAP_EEE_2G5_MASK     BIT(CAPS_HI_2P5GBASET_FD_EEE)
#define HW_ATL_FW2X_CAP_EEE_5G_MASK      BIT(CAPS_HI_5GBASET_FD_EEE)
#define HW_ATL_FW2X_CAP_EEE_10G_MASK     BIT(CAPS_HI_10GBASET_FD_EEE)
#define HW_ATL_FW2X_CAP_PAUSE            BIT(CAPS_HI_PAUSE)
#define HW_ATL_FW2X_CAP_ASYM_PAUSE       BIT(CAPS_HI_ASYMMETRIC_PAUSE)

#define HAL_ATLANTIC_WOL_FILTERS_COUNT   8
#define HAL_ATLANTIC_UTILS_FW2X_MSG_WOL  0x0E

#define HW_ATL_FW_VER_LED                0x03010026U

struct __packed fw2x_msg_wol_pattern {
	u8 mask[16];
	u32 crc;
};

struct __packed fw2x_msg_wol {
	u32 msg_id;
	u8 hw_addr[6];
	u8 magic_packet_enabled;
	u8 filter_count;
	struct fw2x_msg_wol_pattern filter[HAL_ATLANTIC_WOL_FILTERS_COUNT];
	u8 link_up_enabled;
	u8 link_down_enabled;
	u16 reserved;
	u32 link_up_timeout;
	u32 link_down_timeout;
};

static int aq_fw2x_set_link_speed(struct aq_hw_s *self, u32 speed);
static int aq_fw2x_set_state(struct aq_hw_s *self,
			     enum hal_atl_utils_fw_state_e state);

static int aq_fw2x_init(struct aq_hw_s *self)
{
	int err = 0;

	/* check 10 times by 1ms */
	AQ_HW_WAIT_FOR(0U != (self->mbox_addr =
		       aq_hw_read_reg(self, HW_ATL_FW2X_MPI_MBOX_ADDR)),
		       1000U, 10U);
	AQ_HW_WAIT_FOR(0U != (self->rpc_addr =
		       aq_hw_read_reg(self, HW_ATL_FW2X_MPI_RPC_ADDR)),
		       1000U, 100U);
	return err;
}

static int aq_fw2x_deinit(struct aq_hw_s *self)
{
	int err = aq_fw2x_set_link_speed(self, 0);

	if (!err)
		err = aq_fw2x_set_state(self, MPI_DEINIT);

	return err;
}

static enum hw_atl_fw2x_rate link_speed_mask_2fw2x_ratemask(u32 speed)
{
	enum hw_atl_fw2x_rate rate = 0;

	if (speed & AQ_NIC_RATE_10G)
		rate |= FW2X_RATE_10G;

	if (speed & AQ_NIC_RATE_5G)
		rate |= FW2X_RATE_5G;

	if (speed & AQ_NIC_RATE_5GSR)
		rate |= FW2X_RATE_5G;

	if (speed & AQ_NIC_RATE_2GS)
		rate |= FW2X_RATE_2G5;

	if (speed & AQ_NIC_RATE_1G)
		rate |= FW2X_RATE_1G;

	if (speed & AQ_NIC_RATE_100M)
		rate |= FW2X_RATE_100M;

	return rate;
}

static u32 fw2x_to_eee_mask(u32 speed)
{
	u32 rate = 0;

	if (speed & HW_ATL_FW2X_CAP_EEE_10G_MASK)
		rate |= AQ_NIC_RATE_EEE_10G;
	if (speed & HW_ATL_FW2X_CAP_EEE_5G_MASK)
		rate |= AQ_NIC_RATE_EEE_5G;
	if (speed & HW_ATL_FW2X_CAP_EEE_2G5_MASK)
		rate |= AQ_NIC_RATE_EEE_2GS;
	if (speed & HW_ATL_FW2X_CAP_EEE_1G_MASK)
		rate |= AQ_NIC_RATE_EEE_1G;

	return rate;
}

static u32 eee_mask_to_fw2x(u32 speed)
{
	u32 rate = 0;

	if (speed & AQ_NIC_RATE_EEE_10G)
		rate |= HW_ATL_FW2X_CAP_EEE_10G_MASK;
	if (speed & AQ_NIC_RATE_EEE_5G)
		rate |= HW_ATL_FW2X_CAP_EEE_5G_MASK;
	if (speed & AQ_NIC_RATE_EEE_2GS)
		rate |= HW_ATL_FW2X_CAP_EEE_2G5_MASK;
	if (speed & AQ_NIC_RATE_EEE_1G)
		rate |= HW_ATL_FW2X_CAP_EEE_1G_MASK;

	return rate;
}

static int aq_fw2x_set_link_speed(struct aq_hw_s *self, u32 speed)
{
	u32 val = link_speed_mask_2fw2x_ratemask(speed);

	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL_ADDR, val);

	return 0;
}

static void aq_fw2x_upd_flow_control_bits(struct aq_hw_s *self,
					  u32 *mpi_state, u32 fc)
{
	if (fc & AQ_NIC_FC_RX)
		*mpi_state |= HW_ATL_FW2X_CTRL_PAUSE;
	else
		*mpi_state &= ~HW_ATL_FW2X_CTRL_PAUSE;

	if (fc & AQ_NIC_FC_TX)
		*mpi_state |= HW_ATL_FW2X_CTRL_ASYMMETRIC_PAUSE;
	else
		*mpi_state &= ~HW_ATL_FW2X_CTRL_ASYMMETRIC_PAUSE;
}

static void aq_fw2x_upd_eee_rate_bits(struct aq_hw_s *self,
				      u32 *mpi_opts,
				      u32 eee_speeds)
{
	*mpi_opts &= ~(HW_ATL_FW2X_CAP_EEE_1G_MASK |
		       HW_ATL_FW2X_CAP_EEE_2G5_MASK |
		       HW_ATL_FW2X_CAP_EEE_5G_MASK |
		       HW_ATL_FW2X_CAP_EEE_10G_MASK);

	*mpi_opts |= eee_mask_to_fw2x(eee_speeds);
}

static int aq_fw2x_set_state(struct aq_hw_s *self,
			     enum hal_atl_utils_fw_state_e state)
{
	u32 mpi_state = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);

	switch (state) {
	case MPI_INIT:
		mpi_state &= ~HW_ATL_FW2X_CTRL_LINK_DROP;
		aq_fw2x_upd_eee_rate_bits(self, &mpi_state,
					  self->aq_nic_cfg->eee_speeds);
		aq_fw2x_upd_flow_control_bits(self, &mpi_state,
					      self->aq_nic_cfg->flow_control);
		break;
	case MPI_DEINIT:
		mpi_state |= HW_ATL_FW2X_CTRL_LINK_DROP;
		break;
	case MPI_RESET:
	case MPI_POWER:
		/* No actions */
		break;
	}
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_state);
	return 0;
}

static int aq_fw2x_update_link_status(struct aq_hw_s *self)
{
	u32 mpi_state = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE_ADDR);
	u32 speed = mpi_state & (FW2X_RATE_100M | FW2X_RATE_1G |
				 FW2X_RATE_2G5 | FW2X_RATE_5G | FW2X_RATE_10G);
	struct aq_hw_link_status_s *link_status = &self->aq_link_status;

	if (speed) {
		if (speed & FW2X_RATE_10G)
			link_status->mbps = 10000;
		else if (speed & FW2X_RATE_5G)
			link_status->mbps = 5000;
		else if (speed & FW2X_RATE_2G5)
			link_status->mbps = 2500;
		else if (speed & FW2X_RATE_1G)
			link_status->mbps = 1000;
		else if (speed & FW2X_RATE_100M)
			link_status->mbps = 100;
		else
			link_status->mbps = 10000;
	} else {
		link_status->mbps = 0;
	}

	return 0;
}

int aq_fw2x_get_mac_permanent(struct aq_hw_s *self, u8 *mac)
{
	int err = 0;
	u32 h = 0U;
	u32 l = 0U;
	u32 mac_addr[2] = { 0 };
	u32 efuse_addr = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_EFUSE_ADDR);

	if (efuse_addr != 0) {
		err = hw_atl_utils_fw_downld_dwords(self,
						    efuse_addr + (40U * 4U),
						    mac_addr,
						    ARRAY_SIZE(mac_addr));
		if (err)
			return err;
		mac_addr[0] = __swab32(mac_addr[0]);
		mac_addr[1] = __swab32(mac_addr[1]);
	}

	ether_addr_copy(mac, (u8 *)mac_addr);

	if ((mac[0] & 0x01U) || ((mac[0] | mac[1] | mac[2]) == 0x00U)) {
		unsigned int rnd = 0;

		get_random_bytes(&rnd, sizeof(unsigned int));

		l = 0xE3000000U | (0xFFFFU & rnd) | (0x00 << 16);
		h = 0x8001300EU;

		mac[5] = (u8)(0xFFU & l);
		l >>= 8;
		mac[4] = (u8)(0xFFU & l);
		l >>= 8;
		mac[3] = (u8)(0xFFU & l);
		l >>= 8;
		mac[2] = (u8)(0xFFU & l);
		mac[1] = (u8)(0xFFU & h);
		h >>= 8;
		mac[0] = (u8)(0xFFU & h);
	}
	return err;
}

static int aq_fw2x_update_stats(struct aq_hw_s *self)
{
	int err = 0;
	u32 mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
	u32 orig_stats_val = mpi_opts & HW_ATL_FW2X_CTRL_STATISTICS;

	/* Toggle statistics bit for FW to update */
	mpi_opts = mpi_opts ^ HW_ATL_FW2X_CTRL_STATISTICS;
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	/* Wait FW to report back */
	AQ_HW_WAIT_FOR(orig_stats_val !=
		       (aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR) &
				       HW_ATL_FW2X_CTRL_STATISTICS),
		       1U, 10000U);
	if (err)
		return err;

	return hw_atl_utils_update_stats(self);
}

static int aq_fw2x_get_temp(struct aq_hw_s *self, int *temp)
{
	int err = 0;
	u32 mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
	u32 temp_val = mpi_opts & HW_ATL_FW2X_CTRL_TEMPERATURE;
	u32 temp_res;

	/* Toggle statistics bit for FW to 0x36C.18 (CTRL_TEMPERATURE) */
	mpi_opts = mpi_opts ^ HW_ATL_FW2X_CTRL_TEMPERATURE;
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	/* Wait FW to report back */
	AQ_HW_WAIT_FOR(temp_val !=
		       (aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR) &
			HW_ATL_FW2X_CTRL_TEMPERATURE), 1U, 10000U);
	err = hw_atl_utils_fw_downld_dwords(self,
				self->mbox_addr +
				offsetof(struct hw_aq_atl_utils_mbox, info) +
				offsetof(struct hw_aq_info, phy_temperature),
				&temp_res,
				sizeof(temp_res)/sizeof(u32));

	if (err)
		return err;

	*temp = temp_res  * 100 / 256;
	return 0;
}

static int aq_fw2x_get_cable_len(struct aq_hw_s *self, int *cable_len)
{
	int err = 0;
	u32 cable_len_res;

	err = hw_atl_utils_fw_downld_dwords(self,
				self->mbox_addr +
				offsetof(struct hw_aq_atl_utils_mbox, info) +
				offsetof(struct hw_aq_info, phy_temperature),
				&cable_len_res,
				sizeof(cable_len_res)/sizeof(u32));

	if (err)
		return err;

	*cable_len = (cable_len_res >> 16) & 0xFF;
	return 0;
}

static int aq_fw2x_set_sleep_proxy(struct aq_hw_s *self, u8 *mac)
{
	int err = 0;
	struct hw_aq_atl_utils_fw_rpc *rpc = NULL;
	struct offload_info *cfg = NULL;
	unsigned int rpc_size = 0U;
	u32 mpi_opts;

	rpc_size = sizeof(rpc->msg_id) + sizeof(*cfg);

	err = hw_atl_utils_fw_rpc_wait(self, &rpc);
	if (err < 0)
		goto err_exit;

	memset(rpc, 0, rpc_size);
	cfg = (struct offload_info *)(&rpc->msg_id + 1);

	memcpy(cfg->mac_addr, mac, ETH_ALEN);
	cfg->len = sizeof(*cfg);

	/* Clear bit 0x36C.23 and 0x36C.22 */
	mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
	mpi_opts &= ~HW_ATL_FW2X_CTRL_SLEEP_PROXY;
	mpi_opts &= ~HW_ATL_FW2X_CTRL_LINK_DROP;

	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	err = hw_atl_utils_fw_rpc_call(self, rpc_size);
	if (err < 0)
		goto err_exit;

	/* Set bit 0x36C.23 */
	mpi_opts |= HW_ATL_FW2X_CTRL_SLEEP_PROXY;
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	AQ_HW_WAIT_FOR((aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR) &
			HW_ATL_FW2X_CTRL_SLEEP_PROXY), 1U, 10000U);

err_exit:
	return err;
}

static int aq_fw2x_set_wol_params(struct aq_hw_s *self, u8 *mac)
{
	int err = 0;
	struct fw2x_msg_wol *msg = NULL;
	u32 mpi_opts;

	struct hw_aq_atl_utils_fw_rpc *rpc = NULL;

	err = hw_atl_utils_fw_rpc_wait(self, &rpc);
	if (err < 0)
		goto err_exit;

	msg = (struct fw2x_msg_wol *)rpc;

	msg->msg_id = HAL_ATLANTIC_UTILS_FW2X_MSG_WOL;
	msg->magic_packet_enabled = true;
	memcpy(msg->hw_addr, mac, ETH_ALEN);

	mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
	mpi_opts &= ~(HW_ATL_FW2X_CTRL_SLEEP_PROXY | HW_ATL_FW2X_CTRL_WOL);

	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	err = hw_atl_utils_fw_rpc_call(self, sizeof(*msg));
	if (err < 0)
		goto err_exit;

	/* Set bit 0x36C.24 */
	mpi_opts |= HW_ATL_FW2X_CTRL_WOL;
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	AQ_HW_WAIT_FOR((aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR) &
			HW_ATL_FW2X_CTRL_WOL), 1U, 10000U);

err_exit:
	return err;
}

static int aq_fw2x_set_power(struct aq_hw_s *self, unsigned int power_state,
			     u8 *mac)
{
	int err = 0;

	if (self->aq_nic_cfg->wol & AQ_NIC_WOL_ENABLED) {
		err = aq_fw2x_set_sleep_proxy(self, mac);
		if (err < 0)
			goto err_exit;
		err = aq_fw2x_set_wol_params(self, mac);
	}

err_exit:
	return err;
}

static int aq_fw2x_send_fw_request(struct aq_hw_s *self,
		const struct hw_fw_request_iface *fw_req, size_t size)
{
	int err = 0;
	u32 ctrl2, orig_ctrl2;
	u32 dword_cnt;
	
	/* Write data to drvIface Mailbox */
	dword_cnt = size / sizeof(u32);
	if (size % sizeof(u32))
		dword_cnt++;
	err = hw_atl_utils_fw_upload_dwords(self,
			aq_hw_read_reg(self, HW_ATL_FW2X_MPI_RPC_ADDR),
			(void *)fw_req, dword_cnt);
	if (err < 0)
		goto err_exit;
	
	/* Toggle statistics bit for FW to update */
	ctrl2 = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
	orig_ctrl2 = ctrl2 & BIT(CAPS_HI_FW_REQUEST);
	ctrl2 = ctrl2 ^ BIT(CAPS_HI_FW_REQUEST);
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, ctrl2);
	
	/* Wait FW to report back */
	AQ_HW_WAIT_FOR(orig_ctrl2 !=
			(aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR) &
			 BIT(CAPS_HI_FW_REQUEST)),
			1U, 10000U);

err_exit:
	return err;
}

static void aq_fw3x_enable_ptp(struct aq_hw_s *self, int enable)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))
	u32 ptp_opts = aq_hw_read_reg(self, HW_ATL_FW3X_EXT_STATE_ADDR);
	u32 all_ptp_features = BIT(CAPS_EX_PHY_PTP_EN) |
						   BIT(CAPS_EX_PTP_GPIO_EN);

	if (enable)
		ptp_opts |= all_ptp_features;
	else
		ptp_opts &= ~all_ptp_features;

	aq_hw_write_reg(self, HW_ATL_FW3X_EXT_CONTROL_ADDR, ptp_opts);
#endif
}

static int aq_fw2x_led_control(struct aq_hw_s *self, u32 mode)
{
	if (HW_ATL_FW_VER_LED > self->fw_ver_actual)
		return -EOPNOTSUPP;
	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_LED_ADDR, mode);
	return 0;
}

static int aq_fw2x_set_eee_rate(struct aq_hw_s *self, u32 speed)
{
	u32 mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);

	aq_fw2x_upd_eee_rate_bits(self, &mpi_opts, speed);

	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	return 0;
}

static int aq_fw2x_get_eee_rate(struct aq_hw_s *self, u32 *rate,
				u32 *supported_rates)
{
	int err = 0;
	u32 caps_hi;
	u32 mpi_state;

	err = hw_atl_utils_fw_downld_dwords(self,
				self->mbox_addr +
				offsetof(struct hw_aq_atl_utils_mbox, info) +
				offsetof(struct hw_aq_info, caps_hi),
				&caps_hi,
				sizeof(caps_hi)/sizeof(u32));

	if (err)
		return err;

	*supported_rates = fw2x_to_eee_mask(caps_hi);

	mpi_state = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR);
	*rate = fw2x_to_eee_mask(mpi_state);

	return err;
}

static int aq_fw2x_renegotiate(struct aq_hw_s *self)
{
	u32 mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);

	mpi_opts |= HW_ATL_FW2X_CTRL_FORCE_RECONNECT;

	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);

	return 0;
}

static int aq_fw2x_set_flow_control(struct aq_hw_s *self)
{
	u32 mpi_state = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);

	aq_fw2x_upd_flow_control_bits(self, &mpi_state,
				      self->aq_nic_cfg->flow_control);

	aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_state);

	return 0;
}

static u32 aq_fw2x_get_flow_control(struct aq_hw_s *self, u32 *fcmode)
{
	u32 mpi_state = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_STATE2_ADDR);

	*fcmode = ((mpi_state & HW_ATL_FW2X_CAP_PAUSE) ? AQ_NIC_FC_RX : 0) |
		  ((mpi_state & HW_ATL_FW2X_CAP_ASYM_PAUSE) ? AQ_NIC_FC_TX : 0);
	return 0;
}

static int aq_fw2x_set_phyloopback(struct aq_hw_s *self, u32 mode, bool enable)
{
	u32 mpi_opts;

	switch (mode) {
	case AQ_HW_LOOPBACK_PHYINT_SYS:
		mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
		if (enable)
			mpi_opts |= HW_ATL_FW2X_CTRL_INT_LOOPBACK;
		else
			mpi_opts &= ~HW_ATL_FW2X_CTRL_INT_LOOPBACK;
		aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);
		break;
	case AQ_HW_LOOPBACK_PHYEXT_SYS:
		mpi_opts = aq_hw_read_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR);
		if (enable)
			mpi_opts |= HW_ATL_FW2X_CTRL_EXT_LOOPBACK;
		else
			mpi_opts &= ~HW_ATL_FW2X_CTRL_EXT_LOOPBACK;
		aq_hw_write_reg(self, HW_ATL_FW2X_MPI_CONTROL2_ADDR, mpi_opts);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

const struct aq_fw_ops aq_fw_2x_ops = {
	.init               = aq_fw2x_init,
	.deinit             = aq_fw2x_deinit,
	.reset              = NULL,
	.renegotiate        = aq_fw2x_renegotiate,
	.get_mac_permanent  = aq_fw2x_get_mac_permanent,
	.set_link_speed     = aq_fw2x_set_link_speed,
	.set_state          = aq_fw2x_set_state,
	.update_link_status = aq_fw2x_update_link_status,
	.update_stats       = aq_fw2x_update_stats,
	.set_power          = aq_fw2x_set_power,
	.get_temp           = aq_fw2x_get_temp,
	.get_cable_len      = aq_fw2x_get_cable_len,
	.set_eee_rate       = aq_fw2x_set_eee_rate,
	.get_eee_rate       = aq_fw2x_get_eee_rate,
	.set_flow_control   = aq_fw2x_set_flow_control,
	.get_flow_control   = aq_fw2x_get_flow_control,
	.send_fw_request    = aq_fw2x_send_fw_request,
	.enable_ptp         = aq_fw3x_enable_ptp,
	.led_control        = aq_fw2x_led_control,
	.set_phyloopback    = aq_fw2x_set_phyloopback,
};
