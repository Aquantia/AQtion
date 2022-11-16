// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_main.c: Main file for aQuantia Linux driver. */

#include "aq_main.h"
#include "aq_nic.h"
#include "aq_pci_func.h"
#include "aq_ethtool.h"
#include "aq_drvinfo.h"
#include "aq_ptp.h"
#ifdef TSN_SUPPORT
#include "aq_tsn.h"
#endif
#include "aq_filters.h"
#include "aq_hw_utils.h"

#include <linux/pm_runtime.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/stat.h>
#include <linux/string.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#include <uapi/linux/stat.h>
#endif
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/pkt_cls.h>
#include <linux/ptp_classify.h>

MODULE_LICENSE("GPL v2");
MODULE_VERSION(AQ_CFG_DRV_VERSION);
MODULE_AUTHOR(AQ_CFG_DRV_AUTHOR);
MODULE_DESCRIPTION(AQ_CFG_DRV_DESC);

static const char aq_ndev_driver_name[] = AQ_CFG_DRV_NAME;

static const struct net_device_ops aq_ndev_ops;

static struct workqueue_struct *aq_ndev_wq;

void aq_ndev_schedule_work(struct work_struct *work)
{
	queue_work(aq_ndev_wq, work);
}

struct net_device *aq_ndev_alloc(void)
{
	struct net_device *ndev = NULL;
	struct aq_nic_s *aq_nic = NULL;

	ndev = alloc_etherdev_mq(sizeof(struct aq_nic_s), AQ_HW_QUEUES_MAX);
	if (!ndev)
		return NULL;

	aq_nic = netdev_priv(ndev);
	aq_nic->ndev = ndev;
	ndev->netdev_ops = &aq_ndev_ops;
	ndev->ethtool_ops = &aq_ethtool_ops;

	return ndev;
}

static int aq_ndev_open(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0;

	pm_runtime_get_sync(&aq_nic->pdev->dev);

	err = aq_nic_init(aq_nic);
	if (err < 0) {
		aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "Nic init failed, err = %d\n", err);
		goto err_exit;
	}
	err = aq_nic_start(aq_nic);
	if (err < 0) {
		aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "Nic start failed, err = %d\n", err);
		goto err_exit;
	}

	aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "Netdev open successful\n");
err_exit:
	if (err < 0)
		aq_nic_deinit(aq_nic, true);

	aq_utils_obj_set(&aq_nic->aq_hw->flags, AQ_HW_FLAG_STARTED);
	pm_runtime_put(&aq_nic->pdev->dev);

	return err;
}

static int aq_ndev_close(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0;

	pm_runtime_get_sync(&aq_nic->pdev->dev);

	err = aq_nic_stop(aq_nic);
	if (err < 0) {
		aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "Nic stop failed, err = %d\n", err);
		goto err_exit;
	}

	aq_nic_deinit(aq_nic, true);

	aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "Netdev close successful\n");
err_exit:
	aq_utils_obj_clear(&aq_nic->aq_hw->flags, AQ_HW_FLAG_STARTED);
	pm_runtime_put_sync(&aq_nic->pdev->dev);

	return err;
}

static netdev_tx_t aq_ndev_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	if (unlikely(aq_utils_obj_test(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP))) {
		/* Hardware adds the Timestamp for PTPv2 802.AS1
		 * and PTPv2 IPv4 UDP.
		 * We have to push even general 320 port messages to the ptp
		 * queue explicitly. This is a limitation of current firmware
		 * and hardware PTP design of the chip. Otherwise ptp stream
		 * will fail to sync
		 */
		if (unlikely(((ip_hdr(skb)->version == 4) &&
				(ip_hdr(skb)->protocol == IPPROTO_UDP) &&
				((udp_hdr(skb)->dest == htons(PTP_EV_PORT)) ||
				(udp_hdr(skb)->dest == htons(320)))) ||
			((ipv6_hdr(skb)->version == 6) &&
				(udp_hdr(skb)->dest == htons(PTP_EV_PORT)))))
			return aq_ptp_xmit(aq_nic, skb);

		if (unlikely(eth_hdr(skb)->h_proto == htons(ETH_P_1588)))
			return aq_ptp_xmit(aq_nic, skb);
	}
#endif

	skb_tx_timestamp(skb);
	return aq_nic_xmit(aq_nic, skb);
}

static int aq_ndev_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err;

	err = aq_nic_set_mtu(aq_nic, new_mtu + ETH_HLEN);

	if (err < 0)
		goto err_exit;
	ndev->mtu = new_mtu;

	aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "MTU updated\n");
err_exit:
	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static int aq_ndev_set_vlan_ctag_filter(struct aq_nic_s *aq_nic,
					const bool enable)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
	/* Pre-4.17 kernel don't notify the driver about vlans on
	 * HW_VLAN_CTAG_FILTER feature toggle, which puts the driver
	 * into an inconsistent state.
	 * Keep track to notify the user, if he's in trouble.
	 */
	static bool vlan_filter_toggled;
#endif

	if (!enable) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
		vlan_filter_toggled = true;
#endif
		return aq_filters_vlans_off(aq_nic);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
	if (vlan_filter_toggled) {
		netdev_warn(aq_nic->ndev,
			    "%s toggle is broken in this kernel version.",
			    "VLAN_CTAG_FILTER (rx-vlan-filter)");
		netdev_warn(aq_nic->ndev, "%s",
			    "Reload the driver to re-apply vlan filters.");
	}
#endif

	return aq_filters_vlans_on(aq_nic);
}
#endif /* 3.10.0 */

static int aq_ndev_set_features(struct net_device *ndev,
				netdev_features_t features)
{
	bool is_vlan_tx_insert = !!(features & NETIF_F_HW_VLAN_CTAG_TX);
	bool is_vlan_rx_strip = !!(features & NETIF_F_HW_VLAN_CTAG_RX);
	netdev_features_t changed_features = features ^ ndev->features;
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	bool need_ndev_restart = false;
	struct aq_nic_cfg_s *aq_cfg;
	bool is_lro = false;
	int err = 0;

	aq_pr_verbose(aq_nic, AQ_MSG_DEBUG, "Netdev features: old = 0x%llx new = 0x%llx\n",
		      ndev->features, features);
	aq_cfg = aq_nic_get_cfg(aq_nic);
	aq_cfg->features = features;

	pm_runtime_get_sync(&aq_nic->pdev->dev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	if (changed_features & NETIF_F_NTUPLE) {
		if (aq_nic->ndev->features & NETIF_F_NTUPLE) {
			err = aq_clear_rxnfc_all_rules(aq_nic);
			if (unlikely(err))
				goto err_exit;
		}
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	if (changed_features & NETIF_F_HW_VLAN_CTAG_FILTER) {
		err = aq_ndev_set_vlan_ctag_filter(
			aq_nic,
			!!(features & NETIF_F_HW_VLAN_CTAG_FILTER));

		if (unlikely(err))
			goto err_exit;
	}
#endif

	if (aq_cfg->aq_hw_caps->hw_features & NETIF_F_LRO) {
		is_lro = features & NETIF_F_LRO;

		if (aq_cfg->is_lro != is_lro) {
			aq_cfg->is_lro = is_lro;
			need_ndev_restart = true;
		}
	}

	if (changed_features & NETIF_F_RXCSUM) {
		err = aq_nic->aq_hw_ops->hw_set_offload(aq_nic->aq_hw,
							aq_cfg);

		if (unlikely(err))
			goto err_exit;
	}

	if (aq_cfg->is_vlan_rx_strip != is_vlan_rx_strip) {
		aq_cfg->is_vlan_rx_strip = is_vlan_rx_strip;
		need_ndev_restart = true;
	}
	if (aq_cfg->is_vlan_tx_insert != is_vlan_tx_insert) {
		aq_cfg->is_vlan_tx_insert = is_vlan_tx_insert;
		need_ndev_restart = true;
	}

	if (need_ndev_restart && netif_running(ndev)) {
		aq_ndev_close(ndev);
		aq_ndev_open(ndev);
	}

err_exit:
	pm_runtime_put(&aq_nic->pdev->dev);
	return err;
}
#endif

static int aq_ndev_set_mac_address(struct net_device *ndev, void *addr)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);
	int err = 0;

	err = eth_mac_addr(ndev, addr);
	if (err < 0)
		goto err_exit;

	if (pm_runtime_active(&aq_nic->pdev->dev))
		err = aq_nic_set_mac(aq_nic, ndev);

err_exit:
	return err;
}

static void aq_ndev_set_multicast_settings(struct net_device *ndev)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	(void)aq_nic_set_multicast_list(aq_nic, ndev);
}

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
static int aq_ndev_config_hwtstamp(struct aq_nic_s *aq_nic,
				   struct hwtstamp_config *config)
{
	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "config->flags = %d config->tx_type =0x%x\n",
			config->flags, config->tx_type);
	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
	case HWTSTAMP_TX_ON:
		break;
	default:
		return -ERANGE;
	}

	return aq_ptp_hwtstamp_config_set(aq_nic->aq_ptp, config);
}
#endif

static int aq_ndev_hwtstamp_set(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	struct hwtstamp_config config;
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	int ret_val;
#endif

	if (!aq_nic->aq_ptp)
		return -EOPNOTSUPP;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;
#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	ret_val = aq_ndev_config_hwtstamp(aq_nic, &config);
	if (ret_val)
		return ret_val;
#endif

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
	       -EFAULT : 0;
}

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
static int aq_ndev_hwtstamp_get(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	struct hwtstamp_config config;

	if (!aq_nic->aq_ptp)
		return -EOPNOTSUPP;

	aq_ptp_hwtstamp_config_get(aq_nic->aq_ptp, &config);
	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
	       -EFAULT : 0;
}
#endif

static int aq_ndev_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct aq_nic_s *aq_nic = netdev_priv(netdev);
	int res = -EOPNOTSUPP;

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "Ndev ioctl cmd = 0x%x\n", cmd);
	pm_runtime_get_sync(&aq_nic->pdev->dev);

	switch (cmd) {
	case SIOCSHWTSTAMP:
		res = aq_ndev_hwtstamp_set(aq_nic, ifr);
		break;

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)
	case SIOCGHWTSTAMP:
		res = aq_ndev_hwtstamp_get(aq_nic, ifr);
		break;
#ifdef TSN_SUPPORT
	case SIOCINITTSN:
		res = aq_tsn_init(aq_nic, ifr);
		break;
	case SIOCRELEASETSN:
		res = aq_tsn_release(aq_nic, ifr);
		break;
	case SIOCALLOCDMABUF:
		res = aq_tsn_alloc_dma_buf(aq_nic, ifr);
		break;
	case SIOCFREEDMABUF:
		res = aq_tsn_free_dma_buf(aq_nic, ifr);
		break;
	case SIOCLINKCMD:
		res = aq_tsn_get_link(aq_nic, ifr);
		break;
#endif
	case AQ_PTP_SYNC_CFG: {
		struct aq_ptp_ext_gpio_event sync = {0};

		if (copy_from_user(&sync, ifr->ifr_data,
				sizeof(struct aq_ptp_ext_gpio_event))) {
			res = -EFAULT;
			break;
		}

		res = aq_ptp_configure_ext_gpio(netdev, &sync);
		break;
	}
#endif
	}

	pm_runtime_put(&aq_nic->pdev->dev);
	return res;
}

static int aq_ndo_vlan_rx_add_vid(struct net_device *ndev, __be16 proto,
				  u16 vid)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	if (!aq_nic->aq_hw_ops->hw_filter_vlan_set)
		return -EOPNOTSUPP;

	set_bit(vid, aq_nic->active_vlans);
	if (pm_runtime_active(&aq_nic->pdev->dev))
		return aq_filters_vlans_update(aq_nic);
	else
		return 0;
}

static int aq_ndo_vlan_rx_kill_vid(struct net_device *ndev, __be16 proto,
				   u16 vid)
{
	struct aq_nic_s *aq_nic = netdev_priv(ndev);

	if (!aq_nic->aq_hw_ops->hw_filter_vlan_set)
		return -EOPNOTSUPP;

	clear_bit(vid, aq_nic->active_vlans);

	if (-ENOENT == aq_del_fvlan_by_vlan(aq_nic, vid)) {
		if (pm_runtime_active(&aq_nic->pdev->dev))
			return aq_filters_vlans_update(aq_nic);
		else
			return 0;
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0) || \
	RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 3)
static int aq_validate_mqprio_opt(struct aq_nic_s *self,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0) || \
		RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 6)
				  struct tc_mqprio_qopt_offload *mqprio,
#endif
				  const unsigned int num_tc)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0) || \
		RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 6)
	const bool has_min_rate = !!(mqprio->flags & TC_MQPRIO_F_MIN_RATE);
#endif
	struct aq_nic_cfg_s *aq_nic_cfg = aq_nic_get_cfg(self);
	const unsigned int tcs_max = min_t(u8, aq_nic_cfg->aq_hw_caps->tcs_max,
					   AQ_CFG_TCS_MAX);

	if (num_tc > tcs_max) {
		netdev_err(self->ndev, "Too many TCs requested\n");
		return -EOPNOTSUPP;
	}

	if (num_tc != 0 && !is_power_of_2(num_tc)) {
		netdev_err(self->ndev, "TC count should be power of 2\n");
		return -EOPNOTSUPP;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0) || \
		RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 6)
	if (has_min_rate && !ATL_HW_IS_CHIP_FEATURE(self->aq_hw, ANTIGUA)) {
		netdev_err(self->ndev, "Min tx rate is not supported\n");
		return -EOPNOTSUPP;
	}
#endif

	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0) || \
		RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 6)
static int aq_ndo_setup_tc(struct net_device *dev, enum tc_setup_type type,
			   void *type_data)
{
	struct tc_mqprio_qopt_offload *mqprio = type_data;
	struct aq_nic_s *aq_nic = netdev_priv(dev);
	bool has_min_rate;
	bool has_max_rate;
	int err;
	int i;

	if (type != TC_SETUP_QDISC_MQPRIO)
		return -EOPNOTSUPP;

	has_min_rate = !!(mqprio->flags & TC_MQPRIO_F_MIN_RATE);
	has_max_rate = !!(mqprio->flags & TC_MQPRIO_F_MAX_RATE);

	err = aq_validate_mqprio_opt(aq_nic, mqprio, mqprio->qopt.num_tc);
	if (err)
		return err;

	for (i = 0; i < mqprio->qopt.num_tc; i++) {
		if (has_max_rate) {
			u64 max_rate = mqprio->max_rate[i];

			do_div(max_rate, AQ_MBPS_DIVISOR);
			aq_nic_setup_tc_max_rate(aq_nic, i, (u32)max_rate);
		}

		if (has_min_rate) {
			u64 min_rate = mqprio->min_rate[i];

			do_div(min_rate, AQ_MBPS_DIVISOR);
			aq_nic_setup_tc_min_rate(aq_nic, i, (u32)min_rate);
		}
	}

	return aq_nic_setup_tc_mqprio(aq_nic, mqprio->qopt.num_tc,
				      mqprio->qopt.prio_tc_map);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || \
		RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5) || \
		SLE_VERSION_CODE >= SLE_VERSION(15, 0, 0)
static int aq_ndo_setup_tc(struct net_device *dev, enum tc_setup_type type,
			   void *type_data)
{
	struct aq_nic_s *aq_nic = netdev_priv(dev);
	struct tc_mqprio_qopt *mqprio = type_data;
	int err;

	if (type != TC_SETUP_QDISC_MQPRIO)
		return -EOPNOTSUPP;

	err = aq_validate_mqprio_opt(aq_nic, mqprio->num_tc);
	if (err)
		return err;

	return aq_nic_setup_tc_mqprio(aq_nic, mqprio->num_tc,
				      mqprio->prio_tc_map);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0) || \
	RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 3)
static int aq_ndo_setup_tc(struct net_device *dev, u32 handle, __be16 protocol,
			   struct tc_to_netdev *tc)
{
	struct aq_nic_s *aq_nic = netdev_priv(dev);
	int err;

	if (tc->type != TC_SETUP_QDISC_MQPRIO)
		return -EOPNOTSUPP;

	err = aq_validate_mqprio_opt(aq_nic, tc->tc);
	if (err)
		return err;

	return aq_nic_setup_tc_mqprio(aq_nic, tc->tc, NULL);
}
#endif

static const struct net_device_ops aq_ndev_ops = {
	.ndo_open = aq_ndev_open,
	.ndo_stop = aq_ndev_close,
	.ndo_start_xmit = aq_ndev_start_xmit,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
	.ndo_set_multicast_list = aq_ndev_set_multicast_settings,
#else
	.ndo_set_rx_mode = aq_ndev_set_multicast_settings,
#endif
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5) && \
     RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0))
	.extended.ndo_change_mtu = aq_ndev_change_mtu,
#else
	.ndo_change_mtu = aq_ndev_change_mtu,
#endif
	.ndo_set_mac_address = aq_ndev_set_mac_address,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	.ndo_set_features = aq_ndev_set_features,
#endif
	.ndo_do_ioctl = aq_ndev_ioctl,
	.ndo_vlan_rx_add_vid = aq_ndo_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = aq_ndo_vlan_rx_kill_vid,
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0))
	.extended.ndo_setup_tc_rh = aq_ndo_setup_tc,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	.ndo_setup_tc = aq_ndo_setup_tc,
#endif
};

static int __init aq_ndev_init_module(void)
{
	int ret;

	aq_ndev_wq = create_singlethread_workqueue(aq_ndev_driver_name);
	if (!aq_ndev_wq) {
		pr_err("Failed to create workqueue\n");
		return -ENOMEM;
	}

	ret = aq_pci_func_register_driver();
	if (ret) {
		destroy_workqueue(aq_ndev_wq);
		return ret;
	}
	return 0;
}

static void __exit aq_ndev_exit_module(void)
{
	aq_pci_func_unregister_driver();

	if (aq_ndev_wq) {
		destroy_workqueue(aq_ndev_wq);
		aq_ndev_wq = NULL;
	}
}

module_init(aq_ndev_init_module);
module_exit(aq_ndev_exit_module);
