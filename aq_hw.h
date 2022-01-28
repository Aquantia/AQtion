/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_hw.h: Declaration of abstract interface for NIC hardware specific
 * functions.
 */

#ifndef AQ_HW_H
#define AQ_HW_H

#include "aq_common.h"
#include "aq_rss.h"
#include "hw_atl/hw_atl_utils.h"
#include "hw_atl2/hw_atl2_utils.h"

#define AQ_HW_MAC_COUNTER_HZ   312500000ll
#define AQ_HW_PHY_COUNTER_HZ   160000000ll

enum aq_rx_hw_protocol_value_l3l4 {
	AQ_RX_HW_TCP,
	AQ_RX_HW_UDP,
	AQ_RX_HW_SCTP,
	AQ_RX_HW_ICMP
};

enum aq_rx_hw_action_with_traffic {
	AQ_RX_HW_DISCARD,
	AQ_RX_HW_HOST,
	AQ_RX_HW_MNGMNT,
	AQ_RX_HW_HOST_AND_MNGMNT,
	AQ_RX_HW_WOL
};

enum aq_tc_mode {
	AQ_TC_MODE_INVALID = -1,
	AQ_TC_MODE_8TCS,
	AQ_TC_MODE_4TCS,
};

#define AQ_RX_FIRST_LOC_FVLANID     0U
#define AQ_RX_LAST_LOC_FVLANID	   15U
#define AQ_RX_FIRST_LOC_FETHERT    16U
#define AQ_RX_LAST_LOC_FETHERT	   31U
#define AQ_RX_FIRST_LOC_FL3L4	   32U
#define AQ_RX_LAST_LOC_FL3L4	   39U
#define AQ_RX_MAX_RXNFC_LOC	   AQ_RX_LAST_LOC_FL3L4
#define AQ_VLAN_MAX_FILTERS   \
			(AQ_RX_LAST_LOC_FVLANID - AQ_RX_FIRST_LOC_FVLANID + 1U)
#define AQ_RX_QUEUE_NOT_ASSIGNED   0xFFU

#define AQ_FRAC_PER_NS 0x100000000LL

#define AQ2_HW_PTP_COUNTER_131_AND_OLDER_HZ   125000000ll
#define AQ2_HW_PTP_COUNTER_HZ   156250000ll
#define AQ2_HW_312P5_COUNTER_HZ   312500000ll

/* Used for rate to Mbps conversion */
#define AQ_MBPS_DIVISOR         125000 /* 1000000 / 8 */

/* NIC H/W capabilities */
struct aq_hw_caps_s {
	u64 hw_features;
	u64 link_speed_msk;
	unsigned int hw_priv_flags;
	u32 media_type;
	u32 rxds_max;
	u32 txds_max;
	u32 rxds_min;
	u32 txds_min;
	u32 txhwb_alignment;
	u32 irq_mask;
	u32 vecs;
	u32 mtu;
	u32 mac_regs_count;
	u32 hw_alive_check_addr;
	u8 msix_irqs;
	u8 tcs_max;
	u8 rxd_alignment;
	u8 rxd_size;
	u8 txd_alignment;
	u8 txd_size;
	u8 tx_rings;
	u8 rx_rings;
	bool flow_control;
	bool is_64_dma;
	bool op64bit;
	u32 quirks;
	const char *fw_image_name;
	u32 priv_data_len;
};

struct aq_hw_link_status_s {
	unsigned int mbps;
	bool full_duplex;
	u32 lp_link_speed_msk;
	u32 lp_flow_control;
};

struct aq_stats_s {
	u64 brc;
	u64 btc;
	u64 uprc;
	u64 mprc;
	u64 bprc;
	u64 erpt;
	u64 uptc;
	u64 mptc;
	u64 bptc;
	u64 erpr;
	u64 mbtc;
	u64 bbtc;
	u64 mbrc;
	u64 bbrc;
	u64 ubrc;
	u64 ubtc;
	u64 dpc;
	u64 dma_pkt_rc;
	u64 dma_pkt_tc;
	u64 dma_oct_rc;
	u64 dma_oct_tc;
};

/** Generic hardware diagnostic information.
 * Interface between user frontend and firmware layer.
 * Not all the information could be available.
 */
struct aq_diag_s {
	u32 cable_len;
	u32 phy_temp;
	struct hw_atl_cable_diag cable_diag[4];
	u16 snr_margin[4];
};

#define AQ_HW_IRQ_INVALID 0U
#define AQ_HW_IRQ_LEGACY  1U
#define AQ_HW_IRQ_MSI     2U
#define AQ_HW_IRQ_MSIX    3U

/* Interrupt vectors allocation logic as follows:
 * rx/tx lines - up to the number of cpus or hw limit
 * link interrupt line - service irq - could be skipped if not enough lines
 * PTP line
 * GPIO line
 */
#define AQ_HW_SERVICE_IRQS   1U
#define AQ_HW_PTP_IRQS       2U

#define AQ_HW_POWER_STATE_D0   0U
#define AQ_HW_POWER_STATE_D3   3U

#define	AQ_FW_WAKE_ON_LINK_RTPM BIT(10)

#define AQ_HW_FLAG_STARTED     0x00000004U
#define AQ_HW_FLAG_STOPPING    0x00000008U
#define AQ_HW_FLAG_RESETTING   0x00000010U
#define AQ_HW_FLAG_CLOSING     0x00000020U
#define AQ_HW_PTP_AVAILABLE    0x01000000U
#define AQ_HW_PTP_DPATH_UP     0x02000000U
#define AQ_HW_LINK_DOWN        0x04000000U
#define AQ_HW_FLAG_ERR_UNPLUG  0x40000000U
#define AQ_HW_FLAG_ERR_HW      0x80000000U

#define AQ_HW_FLAG_ERRORS      (AQ_HW_FLAG_ERR_HW | AQ_HW_FLAG_ERR_UNPLUG)

#define AQ_NIC_FLAGS_IS_NOT_READY (AQ_NIC_FLAG_STOPPING | \
			AQ_NIC_FLAG_RESETTING | AQ_NIC_FLAG_CLOSING | \
			AQ_NIC_FLAG_ERR_UNPLUG | AQ_NIC_FLAG_ERR_HW)

#define AQ_NIC_FLAGS_IS_NOT_TX_READY (AQ_NIC_FLAGS_IS_NOT_READY | \
					AQ_NIC_LINK_DOWN)

#define AQ_HW_MEDIA_TYPE_TP    1U
#define AQ_HW_MEDIA_TYPE_FIBRE 2U

#define AQ_HW_TXD_MULTIPLE 8U
#define AQ_HW_RXD_MULTIPLE 8U

#define AQ_HW_QUEUES_MAX                32U
#define AQ_HW_MULTICAST_ADDRESS_MAX     32U

#define AQ_HW_AVB_TC                    1U
#define AQ_HW_PTP_TC                    2U
#define AQ_HW_AVBTS_TC                  3U

#define AQ_HW_LED_BLINK    0x2U
#define AQ_HW_LED_DEFAULT  0x0U

#define AQ_HW_MEDIA_DETECT_CNT 6000

enum aq_priv_flags {
	AQ_HW_LOOPBACK_DMA_SYS,
	AQ_HW_LOOPBACK_PKT_SYS,
	AQ_HW_LOOPBACK_DMA_NET,
	AQ_HW_LOOPBACK_PHYINT_SYS,
	AQ_HW_LOOPBACK_PHYEXT_SYS,
	AQ_HW_DOWNSHIFT,
	AQ_HW_MEDIA_DETECT,
};

enum {
	AQ_HW_PTP_DISABLE = 0,
	AQ_HW_PTP_L2_ENABLE = BIT(1),
	AQ_HW_PTP_L4_ENABLE = BIT(2),
};

#define ATL_TSG_CLOCK_SEL_0 0
#define ATL_TSG_CLOCK_SEL_1 1

enum {
	AQ_HW_PTP_EXT_INT_GPIO0 = 0x1,
	AQ_HW_PTP_EXT_INT_GPIO1 = 0x2,
	AQ_HW_PTP_EXT_INT_GPIO2 = 0x4,
	AQ_HW_PTP_EXT_INT_GPIO3 = 0x8,
	AQ_HW_PTP_EXT_INT_PTM = 0x10,
};

#define AQ_HW_LOOPBACK_MASK	(BIT(AQ_HW_LOOPBACK_DMA_SYS) |\
				 BIT(AQ_HW_LOOPBACK_PKT_SYS) |\
				 BIT(AQ_HW_LOOPBACK_DMA_NET) |\
				 BIT(AQ_HW_LOOPBACK_PHYINT_SYS) |\
				 BIT(AQ_HW_LOOPBACK_PHYEXT_SYS))
#define AQ_HW_DOWNSHIFT_MASK    (BIT(AQ_HW_DOWNSHIFT))
#define AQ_HW_MEDIA_DETECT_MASK (BIT(AQ_HW_MEDIA_DETECT))

#define ATL_HW_CHIP_MIPS         0x00000001U
#define ATL_HW_CHIP_TPO2         0x00000002U
#define ATL_HW_CHIP_RPF2         0x00000004U
#define ATL_HW_CHIP_MPI_AQ       0x00000010U
#define ATL_HW_CHIP_ATLANTIC     0x00400000U
#define ATL_HW_CHIP_ANTIGUA      0x08000000U
#define ATL_HW_CHIP_FPGA         0x00800000U
#define ATL_HW_CHIP_REVISION_A0  0x01000000U
#define ATL_HW_CHIP_REVISION_B0  0x02000000U
#define ATL_HW_CHIP_REVISION_B1  0x04000000U

#define ATL_HW_IS_CHIP_FEATURE(_HW_, _F_) (!!(ATL_HW_CHIP_##_F_ & \
	(_HW_)->chip_features))

struct aq_hw_s {
	atomic_t flags;
	u8 rbl_enabled:1;
	u8 fast_start_enabled:1;
	struct aq_nic_cfg_s *aq_nic_cfg;
	const struct aq_fw_ops *aq_fw_ops;
	void __iomem *mmio;
	struct aq_hw_link_status_s aq_link_status;
	struct hw_atl_utils_mbox mbox;
	struct hw_atl_stats_s last_stats;
	struct aq_stats_s curr_stats;
	u64 speed;
	u32 itr_tx;
	u32 itr_rx;
	unsigned int chip_features;
	u32 fw_ver_actual;
	atomic_t dpc;
	u32 mbox_addr;
	u32 rpc_addr;
	u32 settings_addr;
	u32 rpc_tid;
	struct hw_atl_utils_fw_rpc rpc;
	s64 ptp_clk_offset;
	s8 clk_select;
	u16 phy_id;
	u32 ssid;
	u8 image_required;
	u8 mac_filter_max;
	u8 vlan_filter_max;
	u8 etype_filter_max;
	u8 l3l4_filter_max;
	void *priv;
};

struct aq_ring_s;
struct aq_ring_param_s;
struct sk_buff;
struct aq_rx_filter_l3l4;
struct aq_hw_vlans;

struct aq_hw_chip_info {
	u32 chip_id;
	u32 chip_rev;
};

struct aq_hw_ops {

	int (*hw_ring_tx_xmit)(struct aq_hw_s *self, struct aq_ring_s *aq_ring,
			       unsigned int frags);

	int (*hw_ring_rx_receive)(struct aq_hw_s *self,
				  struct aq_ring_s *aq_ring);

	int (*hw_ring_rx_fill)(struct aq_hw_s *self, struct aq_ring_s *aq_ring,
			       unsigned int sw_tail_old);

	int (*hw_ring_tx_head_update)(struct aq_hw_s *self,
				      struct aq_ring_s *aq_ring);

	int (*hw_set_mac_address)(struct aq_hw_s *self, const u8 *mac_addr);

	int (*hw_soft_reset)(struct aq_hw_s *self);

	int (*hw_prepare)(struct aq_hw_s *self,
			  const struct aq_fw_ops **fw_ops);

	int (*hw_reset)(struct aq_hw_s *self);

	int (*hw_init)(struct aq_hw_s *self, const u8 *mac_addr);

	int (*hw_start)(struct aq_hw_s *self);

	int (*hw_stop)(struct aq_hw_s *self);

	u32 (*hw_get_version)(struct aq_hw_s *self);

	int (*hw_ring_tx_init)(struct aq_hw_s *self, struct aq_ring_s *aq_ring,
			       struct aq_ring_param_s *aq_ring_param);

	int (*hw_ring_tx_start)(struct aq_hw_s *self,
				struct aq_ring_s *aq_ring);

	int (*hw_ring_tx_stop)(struct aq_hw_s *self,
			       struct aq_ring_s *aq_ring);

	int (*hw_ring_rx_init)(struct aq_hw_s *self,
			       struct aq_ring_s *aq_ring,
			       struct aq_ring_param_s *aq_ring_param);

	int (*hw_ring_rx_start)(struct aq_hw_s *self,
				struct aq_ring_s *aq_ring);

	int (*hw_ring_rx_stop)(struct aq_hw_s *self,
			       struct aq_ring_s *aq_ring);

	int (*hw_irq_enable)(struct aq_hw_s *self, u64 mask);

	int (*hw_irq_disable)(struct aq_hw_s *self, u64 mask);

	int (*hw_irq_read)(struct aq_hw_s *self, u64 *mask);

	int (*hw_packet_filter_set)(struct aq_hw_s *self,
				    unsigned int packet_filter);

	int (*hw_filter_l3l4_set)(struct aq_hw_s *self,
				  struct aq_rx_filter_l3l4 *data);

	int (*hw_filter_l2_set)(struct aq_hw_s *self,
				struct aq_rx_filter_l2 *data);

	int (*hw_filter_l2_clear)(struct aq_hw_s *self,
				  struct aq_rx_filter_l2 *data);

	int (*hw_filter_vlan_set)(struct aq_hw_s *self,
				  struct aq_rx_filter_vlan *aq_vlans);

	int (*hw_filter_vlan_ctrl)(struct aq_hw_s *self, bool enable);

	int (*hw_multicast_list_set)(struct aq_hw_s *self,
				     u8 ar_mac[AQ_HW_MULTICAST_ADDRESS_MAX]
				     [ETH_ALEN],
				     u32 count);

	int (*hw_interrupt_moderation_set)(struct aq_hw_s *self);

	int (*hw_rss_set)(struct aq_hw_s *self,
			  struct aq_rss_parameters *rss_params);

	int (*hw_rss_hash_set)(struct aq_hw_s *self,
			       struct aq_rss_parameters *rss_params);

	int (*hw_tc_rate_limit_set)(struct aq_hw_s *self);

	int (*hw_get_regs)(struct aq_hw_s *self,
			   const struct aq_hw_caps_s *aq_hw_caps,
			   u32 *regs_buff);

	struct aq_stats_s *(*hw_get_hw_stats)(struct aq_hw_s *self);

	u32 (*hw_get_fw_version)(struct aq_hw_s *self);

	int (*hw_set_offload)(struct aq_hw_s *self,
			      struct aq_nic_cfg_s *aq_nic_cfg);

	int (*hw_ring_hwts_rx_fill)(struct aq_hw_s *self,
				    struct aq_ring_s *aq_ring);

	int (*hw_ring_hwts_rx_receive)(struct aq_hw_s *self,
				       struct aq_ring_s *ring);

	void (*hw_get_ptp_ts)(struct aq_hw_s *self, u64 *stamp);

	int (*hw_adj_clock_freq)(struct aq_hw_s *self, s32 delta);

	int (*hw_adj_sys_clock)(struct aq_hw_s *self, s64 delta);

	int (*hw_set_sys_clock)(struct aq_hw_s *self, u64 time, u64 ts);

	int (*hw_ts_to_sys_clock)(struct aq_hw_s *self, u64 ts, u64 *time);

	int (*hw_gpio_pulse)(struct aq_hw_s *self, u32 index,
			     u32 clk_sel, u64 start,
			     u32 period, u32 hightime);

	int (*hw_ext_interrupr_en)(struct aq_hw_s *self, int on, u32 flags);

	int (*hw_extts_gpio_enable)(struct aq_hw_s *self, u32 index,
				    u32 channel, int on);

	u64 (*hw_ptp_gpio_get_event)(struct aq_hw_s *aq_hw, u32 channel,
				     u32 *event_count);

	void (*enable_ptp)(struct aq_hw_s *self, unsigned int param,
			   int enable);

	u16 (*rx_extract_ts)(struct aq_hw_s *self, u8 *p, unsigned int len,
			     u64 *timestamp);

	int (*extract_hwts)(struct aq_hw_s *self, u8 *p, unsigned int len,
			    u64 *timestamp);

	u64 (*hw_ring_tx_ptp_get_ts)(struct aq_ring_s *ring);

	int (*hw_tx_ptp_ring_init)(struct aq_hw_s *self,
				     struct aq_ring_s *aq_ring);
	int (*hw_rx_ptp_ring_init)(struct aq_hw_s *self,
				     struct aq_ring_s *aq_ring);
	u32 (*hw_get_clk_sel)(struct aq_hw_s *self);

	int (*hw_set_fc)(struct aq_hw_s *self, u32 fc, u32 tc);

	int (*hw_set_loopback)(struct aq_hw_s *self, u32 mode, bool enable);

	void (*hw_get_chip_info)(struct aq_hw_s *self,
				 struct aq_hw_chip_info *chip_info);

	int (*hw_get_mac_temp)(struct aq_hw_s *self, u32 *temp);
};

struct aq_fw_ops {
	int (*init)(struct aq_hw_s *self);

	int (*deinit)(struct aq_hw_s *self);

	int (*reset)(struct aq_hw_s *self);

	int (*renegotiate)(struct aq_hw_s *self);

	int (*get_mac_permanent)(struct aq_hw_s *self, u8 *mac);

	int (*set_link_speed)(struct aq_hw_s *self, u32 speed);

	int (*set_state)(struct aq_hw_s *self,
			 enum hal_atl_utils_fw_state_e state);

	int (*update_link_status)(struct aq_hw_s *self);

	int (*update_stats)(struct aq_hw_s *self);

	int (*get_mac_temp)(struct aq_hw_s *self, int *temp);

	int (*get_phy_temp)(struct aq_hw_s *self, int *temp);

	int (*get_cable_len)(struct aq_hw_s *self, int *cable_len);

	u32 (*get_flow_control)(struct aq_hw_s *self, u32 *fcmode);

	int (*set_flow_control)(struct aq_hw_s *self);

	int (*led_control)(struct aq_hw_s *self, u32 mode);

	int (*set_phyloopback)(struct aq_hw_s *self, u32 mode, bool enable);

	int (*set_power)(struct aq_hw_s *self, unsigned int power_state,
			 const u8 *mac, u32 wol);

	int (*send_fw_request)(struct aq_hw_s *self,
			       const struct hw_fw_request_iface *fw_req,
			       size_t size);

	void (*enable_ptp)(struct aq_hw_s *self, int enable);

	void (*adjust_ptp)(struct aq_hw_s *self, uint64_t adj);

	int (*set_eee_rate)(struct aq_hw_s *self, u32 speed);

	int (*get_eee_rate)(struct aq_hw_s *self, u32 *rate,
			    u32 *supported_rates);

	int (*set_downshift)(struct aq_hw_s *self, u32 counter);

	int (*set_media_detect)(struct aq_hw_s *self, bool enable);

	int (*get_cable_diag_capable)(struct aq_hw_s *self, bool *capable);

	int (*run_tdr_diag)(struct aq_hw_s *self);

	int (*get_diag_data)(struct aq_hw_s *self, struct aq_diag_s *diag);

	int (*get_snr_margin_capable)(struct aq_hw_s *self, bool *capable);

	int (*get_snr_margins)(struct aq_hw_s *self, struct aq_diag_s *diag);

	u32 (*get_link_capabilities)(struct aq_hw_s *self);

	int (*send_macsec_req)(struct aq_hw_s *self,
			       struct macsec_msg_fw_request *msg,
			       struct macsec_msg_fw_response *resp);
};

#endif /* AQ_HW_H */
