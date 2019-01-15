/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_ethtool.c: Definition of ethertool related functions. */

#include "aq_ethtool.h"
#include "aq_nic.h"
#include "aq_vec.h"
#include "aq_main.h"
#include "aq_ptp.h"
#include "aq_filters.h"

#include <linux/ptp_clock_kernel.h>

static void aq_ethtool_get_regs(struct net_device *ndev,
				struct ethtool_regs *regs, void *p)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	u32 regs_count = aq_nic_get_regs_count(aq_nic);

	memset(p, 0, regs_count * sizeof(u32));
	aq_nic_get_regs(aq_nic, regs, p);
}

static int aq_ethtool_get_regs_len(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	u32 regs_count = aq_nic_get_regs_count(aq_nic);

	return regs_count * sizeof(u32);
}

static u32 aq_ethtool_get_link(struct net_device *ndev)
{
	return ethtool_op_get_link(ndev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
static int aq_ethtool_get_link_ksettings(struct net_device *ndev,
					 struct ethtool_link_ksettings *cmd)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	aq_nic_get_link_ksettings(aq_nic, cmd);
	cmd->base.speed = netif_carrier_ok(ndev) ?
				aq_nic_get_link_speed(aq_nic) : 0U;

	return 0;
}

static int
aq_ethtool_set_link_ksettings(struct net_device *ndev,
			      const struct ethtool_link_ksettings *cmd)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	return aq_nic_set_link_ksettings(aq_nic, cmd);
}
#else
static int aq_ethtool_get_settings(struct net_device *ndev,
				   struct ethtool_cmd *cmd)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);


	aq_nic_get_link_settings(aq_nic, cmd);
	ethtool_cmd_speed_set(cmd, netif_carrier_ok(ndev) ?
				aq_nic_get_link_speed(aq_nic) : 0U);

	return 0;
}

static int aq_ethtool_set_settings(struct net_device *ndev,
				   struct ethtool_cmd *cmd)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0U;

	err = aq_nic_set_link_settings(aq_nic, cmd);

	return err;
}
#endif

static const char aq_ethtool_stat_names[][ETH_GSTRING_LEN] = {
	"InPackets",
	"InUCast",
	"InMCast",
	"InBCast",
	"InErrors",
	"OutPackets",
	"OutUCast",
	"OutMCast",
	"OutBCast",
	"InUCastOctets",
	"OutUCastOctets",
	"InMCastOctets",
	"OutMCastOctets",
	"InBCastOctets",
	"OutBCastOctets",
	"InOctets",
	"OutOctets",
	"InPacketsDma",
	"OutPacketsDma",
	"InOctetsDma",
	"OutOctetsDma",
	"InDroppedDma",
};

static const char aq_ethtool_queue_stat_names[][ETH_GSTRING_LEN] = {
	"Queue[%d] InPackets",
	"Queue[%d] OutPackets",
	"Queue[%d] Restarts",
	"Queue[%d] InJumboPackets",
	"Queue[%d] InLroPackets",
	"Queue[%d] InErrors",
};

/** This sequence should follow AQ_HW_LOOPBACK_* defines
 */
static const char aq_ethtool_priv_flag_names[][ETH_GSTRING_LEN] = {
	"DMASystemLoopback",
	"PKTSystemLoopback",
	"DMANetworkLoopback",
	"PHYInternalLoopback",
	"PHYExternalLoopback",
};

static void aq_ethtool_stats(struct net_device *ndev,
			     struct ethtool_stats *stats, u64 *data)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);

	memset(data, 0, (ARRAY_SIZE(aq_ethtool_stat_names) +
			 ARRAY_SIZE(aq_ethtool_queue_stat_names) *
			 cfg->vecs) * sizeof(u64));
	aq_nic_get_stats(aq_nic, data);
}

static void aq_ethtool_get_drvinfo(struct net_device *ndev,
				   struct ethtool_drvinfo *drvinfo)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	struct pci_dev *pdev = to_pci_dev(ndev->dev.parent);
	u32 firmware_version = aq_nic_get_fw_version(aq_nic);
	u32 regs_count = aq_nic_get_regs_count(aq_nic);

	strlcat(drvinfo->driver, aq_ndev_driver_name, sizeof(drvinfo->driver));
	strlcat(drvinfo->version, AQ_CFG_DRV_VERSION, sizeof(drvinfo->version));

	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "%u.%u.%u", firmware_version >> 24,
		 (firmware_version >> 16) & 0xFFU, firmware_version & 0xFFFFU);

	strlcpy(drvinfo->bus_info, pdev ? pci_name(pdev) : "",
		sizeof(drvinfo->bus_info));
	drvinfo->n_stats = ARRAY_SIZE(aq_ethtool_stat_names) +
			   cfg->vecs * ARRAY_SIZE(aq_ethtool_queue_stat_names);
	drvinfo->testinfo_len = 0;
	drvinfo->regdump_len = regs_count;
	drvinfo->eedump_len = 0;
}

static void aq_ethtool_get_strings(struct net_device *ndev,
				   u32 stringset, u8 *data)
{
	int i, si;
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	u8 *p = data;

	switch (stringset) {
	case  ETH_SS_STATS:
		memcpy(p, aq_ethtool_stat_names,
		       sizeof(aq_ethtool_stat_names));
		p = p + sizeof(aq_ethtool_stat_names);
		for (i = 0; i < cfg->vecs; i++) {
			for (si = 0;
				si < ARRAY_SIZE(aq_ethtool_queue_stat_names);
				si++) {
				snprintf(p, ETH_GSTRING_LEN,
					 aq_ethtool_queue_stat_names[si], i);
				p += ETH_GSTRING_LEN;
			}
		}
		break;
	case  ETH_SS_PRIV_FLAGS:
		memcpy(p, aq_ethtool_priv_flag_names,
		       sizeof(aq_ethtool_priv_flag_names));
		break;
	}
}

static int aq_ethtool_set_phys_id(struct net_device *ndev,
				  enum ethtool_phys_id_state state)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_hw_s *hw = aq_nic->aq_hw;
	int ret = 0;

	if (!aq_nic->aq_fw_ops->led_control)
		return -EOPNOTSUPP;
	mutex_lock(&aq_nic->fwreq_mutex);
	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		ret = aq_nic->aq_fw_ops->led_control(hw, AQ_HW_LED_BLINK |
				 AQ_HW_LED_BLINK << 2 | AQ_HW_LED_BLINK << 4);
		break;
	case ETHTOOL_ID_INACTIVE:
		ret = aq_nic->aq_fw_ops->led_control(hw, AQ_HW_LED_DEFAULT);
		break;
	default:
		break;
	}
	mutex_unlock(&aq_nic->fwreq_mutex);
	return ret;
}

static int aq_ethtool_get_sset_count(struct net_device *ndev, int stringset)
{
	int ret = 0;
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);

	switch (stringset) {
	case ETH_SS_STATS:
		ret = ARRAY_SIZE(aq_ethtool_stat_names) +
		      cfg->vecs * ARRAY_SIZE(aq_ethtool_queue_stat_names);
		break;
	case  ETH_SS_PRIV_FLAGS:
		ret = ARRAY_SIZE(aq_ethtool_priv_flag_names);
		break;
	default:
		ret = -EOPNOTSUPP;
	}
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static u32 aq_ethtool_get_rss_indir_size(struct net_device *ndev)
{
	return AQ_CFG_RSS_INDIRECTION_TABLE_MAX;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5))
static u32 aq_ethtool_get_rss_key_size(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);

	return sizeof(cfg->aq_rss.hash_secret_key);
}

#if defined(ETH_RSS_HASH_TOP)
static int aq_ethtool_get_rss(struct net_device *ndev, u32 *indir, u8 *key,
			      u8 *hfunc)
#else
static int aq_ethtool_get_rss(struct net_device *ndev, u32 *indir, u8 *key)
#endif
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	unsigned int i = 0U;

#if defined(ETH_RSS_HASH_TOP)
	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP; /* Toeplitz */
#endif
	if (indir) {
		for (i = 0; i < AQ_CFG_RSS_INDIRECTION_TABLE_MAX; i++)
			indir[i] = cfg->aq_rss.indirection_table[i];
	}
	if (key)
		memcpy(key, cfg->aq_rss.hash_secret_key,
		       sizeof(cfg->aq_rss.hash_secret_key));
	return 0;
}

#if defined(ETH_RSS_HASH_TOP)
static int aq_ethtool_set_rss(struct net_device *netdev, const u32 *indir,
			  const u8 *key, const u8 hfunc)
#else
static int aq_ethtool_set_rss(struct net_device *netdev, const u32 *indir,
			  const u8 *key)
#endif
{
	struct aq_nic_s *aq_nic = netdev_priv(netdev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	unsigned int i = 0U;
	int err = 0;
	u32 rss_entries = cfg->aq_rss.indirection_table_size;

#if defined(ETH_RSS_HASH_TOP)
	/* We do not allow change in unsupported parameters */
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;
#endif

	/* Fill out the redirection table */
	if (indir) {
		/* Verify user input. */
		for (i = 0; i < rss_entries; i++)
			if (indir[i] >= cfg->num_rss_queues)
				return -EINVAL;

		for (i = 0; i < rss_entries; i++)
			cfg->aq_rss.indirection_table[i] = indir[i];
	}

	/* Fill out the rss hash key */
	if (key) {
		memcpy(cfg->aq_rss.hash_secret_key, key,
			sizeof(cfg->aq_rss.hash_secret_key));
		err = aq_nic->aq_hw_ops->hw_rss_hash_set(aq_nic->aq_hw,
			&cfg->aq_rss);
	}

	aq_nic->aq_hw_ops->hw_rss_set(aq_nic->aq_hw, &cfg->aq_rss);

	return err;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static int aq_ethtool_get_rxnfc(struct net_device *ndev,
				struct ethtool_rxnfc *cmd,
				u32 *rule_locs)
#else
static int aq_ethtool_get_rxnfc(struct net_device *ndev,
				struct ethtool_rxnfc *cmd,
				void *rule_locs)
#endif
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	int err = 0;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = cfg->vecs;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = aq_get_rxnfc_count_all_rules(aq_nic);
		break;
	case ETHTOOL_GRXCLSRULE:
		err = aq_get_rxnfc_rule(aq_nic, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		err = aq_get_rxnfc_all_rules(aq_nic, cmd, rule_locs);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
static int aq_ethtool_set_rxnfc(struct net_device *ndev,
				struct ethtool_rxnfc *cmd)
{
	int err = 0;
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		err = aq_add_rxnfc_rule(aq_nic, cmd);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		err = aq_del_rxnfc_rule(aq_nic, cmd);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}
#endif

static int aq_ethtool_get_coalesce(struct net_device *ndev,
				   struct ethtool_coalesce *coal)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);

	if (cfg->itr == AQ_CFG_INTERRUPT_MODERATION_ON ||
	    cfg->itr == AQ_CFG_INTERRUPT_MODERATION_AUTO) {
		coal->rx_coalesce_usecs = cfg->rx_itr;
		coal->tx_coalesce_usecs = cfg->tx_itr;
		coal->rx_max_coalesced_frames = 0;
		coal->tx_max_coalesced_frames = 0;
	} else {
		coal->rx_coalesce_usecs = 0;
		coal->tx_coalesce_usecs = 0;
		coal->rx_max_coalesced_frames = 1;
		coal->tx_max_coalesced_frames = 1;
	}
	return 0;
}

static int aq_ethtool_set_coalesce(struct net_device *ndev,
				   struct ethtool_coalesce *coal)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);

	/* This is not yet supported
	 */
	if (coal->use_adaptive_rx_coalesce || coal->use_adaptive_tx_coalesce)
		return -EOPNOTSUPP;

	/* Atlantic only supports timing based coalescing
	 */
	if (coal->rx_max_coalesced_frames > 1 ||
	    coal->rx_coalesce_usecs_irq ||
	    coal->rx_max_coalesced_frames_irq)
		return -EOPNOTSUPP;

	if (coal->tx_max_coalesced_frames > 1 ||
	    coal->tx_coalesce_usecs_irq ||
	    coal->tx_max_coalesced_frames_irq)
		return -EOPNOTSUPP;

	/* We do not support frame counting. Check this
	 */
	if (!(coal->rx_max_coalesced_frames == !coal->rx_coalesce_usecs))
		return -EOPNOTSUPP;
	if (!(coal->tx_max_coalesced_frames == !coal->tx_coalesce_usecs))
		return -EOPNOTSUPP;

	if (coal->rx_coalesce_usecs > AQ_CFG_INTERRUPT_MODERATION_USEC_MAX ||
	    coal->tx_coalesce_usecs > AQ_CFG_INTERRUPT_MODERATION_USEC_MAX)
		return -EINVAL;

	cfg->itr = AQ_CFG_INTERRUPT_MODERATION_ON;

	cfg->rx_itr = coal->rx_coalesce_usecs;
	cfg->tx_itr = coal->tx_coalesce_usecs;

	return aq_nic_update_interrupt_moderation_settings(aq_nic);
}


static void aq_ethtool_get_wol(struct net_device *ndev,
			       struct ethtool_wolinfo *wol)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);

	wol->supported = WAKE_MAGIC;
	wol->wolopts = 0;

	if (cfg->wol)
		wol->wolopts |= WAKE_MAGIC;
}

static int aq_ethtool_set_wol(struct net_device *ndev,
			      struct ethtool_wolinfo *wol)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	struct pci_dev *pdev = to_pci_dev(ndev->dev.parent);
	int err = 0;

	if (wol->wolopts & WAKE_MAGIC)
		cfg->wol |= AQ_NIC_WOL_ENABLED;
	else
		cfg->wol &= ~AQ_NIC_WOL_ENABLED;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	err = device_set_wakeup_enable(&pdev->dev, wol->wolopts);
#else
	device_set_wakeup_enable(&pdev->dev, wol->wolopts);
#endif

	return err;
}

static int aq_ethtool_get_ts_info(struct net_device *ndev,
				  struct ethtool_ts_info *info)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	ethtool_op_get_ts_info(ndev, info);

	info->so_timestamping |=
		SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;

	info->tx_types =
		BIT(HWTSTAMP_TX_OFF) |
		BIT(HWTSTAMP_TX_ON);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE);

	if (aq_nic->aq_ptp)
		info->rx_filters |= BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
				    BIT(HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
				    BIT(HWTSTAMP_FILTER_PTP_V2_EVENT);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))
	info->phc_index = (aq_nic->aq_ptp) ?
		ptp_clock_index(aq_ptp_get_ptp_clock(aq_nic->aq_ptp)) : -1;
#endif

	return 0;
}

static enum hw_atl_fw2x_rate eee_mask_to_ethtool_mask(u32 speed)
{
	u32 rate = 0;

	if (speed & AQ_NIC_RATE_EEE_10G)
		rate |= SUPPORTED_10000baseT_Full;

	/* This is not supported
	 * if (speed & AQ_NIC_RATE_EEE_5G)
	 *	rate |= SUPPORTED_5000baseX_Full;
	 */

	if (speed & AQ_NIC_RATE_EEE_2GS)
		rate |= SUPPORTED_2500baseX_Full;


	if (speed & AQ_NIC_RATE_EEE_1G)
		rate |= SUPPORTED_1000baseT_Full;

	return rate;
}

static int aq_ethtool_get_eee(struct net_device *ndev, struct ethtool_eee *eee)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0;

	u32 rate, supported_rates;

	if (!aq_nic->aq_fw_ops->get_eee_rate)
		return -EOPNOTSUPP;

	mutex_lock(&aq_nic->fwreq_mutex);
	err = aq_nic->aq_fw_ops->get_eee_rate(aq_nic->aq_hw, &rate,
					      &supported_rates);
	mutex_unlock(&aq_nic->fwreq_mutex);
	if (err < 0)
		return err;

	eee->supported = eee_mask_to_ethtool_mask(supported_rates);

	if (aq_nic->aq_nic_cfg.eee_speeds)
		eee->advertised = eee->supported;

	eee->lp_advertised = eee_mask_to_ethtool_mask(rate);

	eee->eee_enabled = !!eee->advertised;

	eee->tx_lpi_enabled = eee->eee_enabled;
	if (eee->advertised & eee->lp_advertised)
		eee->eee_active = true;

	return 0;
}

static int aq_ethtool_set_eee(struct net_device *ndev, struct ethtool_eee *eee)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *cfg = aq_nic_get_cfg(aq_nic);
	u32 rate, supported_rates;
	int err = 0;

	if (unlikely(!aq_nic->aq_fw_ops->get_eee_rate ||
		     !aq_nic->aq_fw_ops->set_eee_rate))
		return -EOPNOTSUPP;

	mutex_lock(&aq_nic->fwreq_mutex);
	err = aq_nic->aq_fw_ops->get_eee_rate(aq_nic->aq_hw, &rate,
					      &supported_rates);
	mutex_unlock(&aq_nic->fwreq_mutex);
	if (err < 0)
		return err;

	if (eee->eee_enabled) {
		rate = supported_rates;
		cfg->eee_speeds = rate;
	} else {
		rate = 0;
		cfg->eee_speeds = 0;
	}
	mutex_lock(&aq_nic->fwreq_mutex);
	err = aq_nic->aq_fw_ops->set_eee_rate(aq_nic->aq_hw, rate);
	mutex_unlock(&aq_nic->fwreq_mutex);

	return  err;
}

static int aq_ethtool_nway_reset(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0;

	if (unlikely(!aq_nic->aq_fw_ops->renegotiate))
		return -EOPNOTSUPP;

	if (netif_running(ndev)) {
		mutex_lock(&aq_nic->fwreq_mutex);
		err = aq_nic->aq_fw_ops->renegotiate(aq_nic->aq_hw);
		mutex_unlock(&aq_nic->fwreq_mutex);
	}

	return err;
}

static void aq_ethtool_get_pauseparam(struct net_device *ndev,
				      struct ethtool_pauseparam *pause)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int fc = aq_nic->aq_nic_cfg.flow_control;

	pause->autoneg = 0;

	pause->rx_pause = !!(fc & AQ_NIC_FC_RX);
	pause->tx_pause = !!(fc & AQ_NIC_FC_TX);
}

static int aq_ethtool_set_pauseparam(struct net_device *ndev,
				     struct ethtool_pauseparam *pause)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0;

	if (!aq_nic->aq_fw_ops->set_flow_control)
		return -EOPNOTSUPP;

	if (pause->autoneg == AUTONEG_ENABLE)
		return -EOPNOTSUPP;

	if (pause->rx_pause)
		aq_nic->aq_hw->aq_nic_cfg->flow_control |= AQ_NIC_FC_RX;
	else
		aq_nic->aq_hw->aq_nic_cfg->flow_control &= ~AQ_NIC_FC_RX;

	if (pause->tx_pause)
		aq_nic->aq_hw->aq_nic_cfg->flow_control |= AQ_NIC_FC_TX;
	else
		aq_nic->aq_hw->aq_nic_cfg->flow_control &= ~AQ_NIC_FC_TX;

	mutex_lock(&aq_nic->fwreq_mutex);
	err = aq_nic->aq_fw_ops->set_flow_control(aq_nic->aq_hw);
	mutex_unlock(&aq_nic->fwreq_mutex);

	return err;
}

static void aq_get_ringparam(struct net_device *ndev,
			     struct ethtool_ringparam *ring)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *aq_nic_cfg = aq_nic_get_cfg(aq_nic);

	ring->rx_pending = aq_nic_cfg->rxds;
	ring->tx_pending = aq_nic_cfg->txds;

	ring->rx_max_pending = aq_nic_cfg->aq_hw_caps->rxds_max;
	ring->tx_max_pending = aq_nic_cfg->aq_hw_caps->txds_max;
}

static int aq_set_ringparam(struct net_device *ndev,
			    struct ethtool_ringparam *ring)
{
	int err = 0;
	bool ndev_running = netif_running(ndev);
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	struct aq_nic_cfg_s *aq_nic_cfg = aq_nic_get_cfg(aq_nic);
	const struct aq_hw_caps_s *hw_caps = aq_nic_cfg->aq_hw_caps;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending) {
		err = -EOPNOTSUPP;
		goto err_exit;
	}

	if (ndev_running)
		dev_close(ndev);

	aq_nic_free_vectors(aq_nic);

	aq_nic_cfg->rxds = max(ring->rx_pending, hw_caps->rxds_min);
	aq_nic_cfg->rxds = min(aq_nic_cfg->rxds, hw_caps->rxds_max);
	aq_nic_cfg->rxds = ALIGN(aq_nic_cfg->rxds, AQ_HW_RXD_MULTIPLE);

	aq_nic_cfg->txds = max(ring->tx_pending, hw_caps->txds_min);
	aq_nic_cfg->txds = min(aq_nic_cfg->txds, hw_caps->txds_max);
	aq_nic_cfg->txds = ALIGN(aq_nic_cfg->txds, AQ_HW_TXD_MULTIPLE);

	for (aq_nic->aq_vecs = 0; aq_nic->aq_vecs < aq_nic_cfg->vecs;
	     aq_nic->aq_vecs++) {
		aq_nic->aq_vec[aq_nic->aq_vecs] =
		    aq_vec_alloc(aq_nic, aq_nic->aq_vecs, aq_nic_cfg);
		if (unlikely(!aq_nic->aq_vec[aq_nic->aq_vecs])) {
			err = -ENOMEM;
			goto err_exit;
		}
	}
	if (ndev_running)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
		err = dev_open(ndev, NULL);
#else
		err = dev_open(ndev);
#endif

err_exit:
	return err;
}

static u32 aq_get_msg_level(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	return aq_nic->msg_enable;
}

static void aq_set_msg_level(struct net_device *ndev, u32 data)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	aq_nic->msg_enable = data;
}

u32 aq_ethtool_get_priv_flags(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	u32 priv_flags = 0;

	priv_flags |= aq_nic_getloopback(aq_nic) & AQ_HW_LOOPBACK_MASK;

	return priv_flags;
}

int aq_ethtool_set_priv_flags(struct net_device *ndev, u32 flags)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	return aq_nic_setloopback(aq_nic, flags & AQ_HW_LOOPBACK_MASK);
}

const struct ethtool_ops aq_ethtool_ops = {
	.get_link            = aq_ethtool_get_link,
	.get_regs_len        = aq_ethtool_get_regs_len,
	.get_regs            = aq_ethtool_get_regs,
	.get_drvinfo         = aq_ethtool_get_drvinfo,
	.get_strings         = aq_ethtool_get_strings,
	.set_phys_id         = aq_ethtool_set_phys_id,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	.get_rxfh_indir_size = aq_ethtool_get_rss_indir_size,
#endif
	.get_wol             = aq_ethtool_get_wol,
	.set_wol             = aq_ethtool_set_wol,
	.nway_reset          = aq_ethtool_nway_reset,
	.get_ringparam       = aq_get_ringparam,
	.set_ringparam       = aq_set_ringparam,
	.get_eee             = aq_ethtool_get_eee,
	.set_eee             = aq_ethtool_set_eee,
	.get_pauseparam      = aq_ethtool_get_pauseparam,
	.set_pauseparam      = aq_ethtool_set_pauseparam,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5))
	.get_rxfh_key_size   = aq_ethtool_get_rss_key_size,
	.get_rxfh            = aq_ethtool_get_rss,
	.set_rxfh            = aq_ethtool_set_rss,
#endif
	.get_msglevel        = aq_get_msg_level,
	.set_msglevel        = aq_set_msg_level,
	.get_rxnfc           = aq_ethtool_get_rxnfc,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	.set_rxnfc           = aq_ethtool_set_rxnfc,
#endif
	.get_sset_count      = aq_ethtool_get_sset_count,
	.get_ethtool_stats   = aq_ethtool_stats,
	.get_priv_flags      = aq_ethtool_get_priv_flags,
	.set_priv_flags      = aq_ethtool_set_priv_flags,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	.get_link_ksettings  = aq_ethtool_get_link_ksettings,
	.set_link_ksettings  = aq_ethtool_set_link_ksettings,
#else
	.get_settings        = aq_ethtool_get_settings,
	.set_settings        = aq_ethtool_set_settings,
#endif
	.get_coalesce        = aq_ethtool_get_coalesce,
	.set_coalesce        = aq_ethtool_set_coalesce,
	.get_ts_info         = aq_ethtool_get_ts_info,
};
