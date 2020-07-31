/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 * Copyright (C) 2020 Marvell International Ltd.
 */

/* File hw_atl2_internal.h: Definition of Atlantic2 chip specific
 * constants.
 */

#ifndef HW_ATL2_INTERNAL_H
#define HW_ATL2_INTERNAL_H

#include "aq_common.h"

#define HW_ATL2_MTU_JUMBO  16352U
#define HW_ATL2_MTU        1514U

#define HW_ATL2_TX_RINGS 4U
#define HW_ATL2_RX_RINGS 4U

#define HW_ATL2_RINGS_MAX 32U
#define HW_ATL2_TXD_SIZE       (16U)
#define HW_ATL2_RXD_SIZE       (16U)

#define HW_ATL2_MAC_UC   0U
#define HW_ATL2_MAC_MIN  1U
#define HW_ATL2_MAC_MAX  38U

/* interrupts */
#define HW_ATL2_ERR_INT 8U
#define HW_ATL2_INT_MASK  (0xFFFFFFFFU)

#define HW_ATL2_TXD_CTL_DESC_TYPE_TXTS  (0x00000003)
#define HW_ATL2_TXD_CTL_TS_EN       (0x40000000)
#define HW_ATL2_TXD_CTL_TS_TSG0      (0x80000000)

#define HW_ATL2_TXBUF_MAX              128U
#define HW_ATL2_PTP_TXBUF_SIZE           8U

#define HW_ATL2_RXBUF_MAX              172U
#define HW_ATL2_PTP_RXBUF_SIZE          16U
#define HW_ATL2_PTP_HWTS_RXBUF_SIZE      8U

#define HW_ATL2_RSS_REDIRECTION_MAX 64U

#define HW_ATL2_TC_MAX 8U
#define HW_ATL2_RSS_MAX 8U

#define HW_ATL2_INTR_MODER_MAX  0x1FF
#define HW_ATL2_INTR_MODER_MIN  0xFF

#define HW_ATL2_MIN_RXD \
	(ALIGN(AQ_CFG_SKB_FRAGS_MAX + 1U, AQ_HW_RXD_MULTIPLE))
#define HW_ATL2_MIN_TXD \
	(ALIGN(AQ_CFG_SKB_FRAGS_MAX + 1U, AQ_HW_TXD_MULTIPLE))

#define HW_ATL2_MAX_RXD 8184U
#define HW_ATL2_MAX_TXD 8184U

#define HW_ATL2_FW_SM_ACT_RSLVR  0x3U

#define HW_ATL2_RPF_TAG_UC_OFFSET      0x0
#define HW_ATL2_RPF_TAG_ALLMC_OFFSET   0x6
#define HW_ATL2_RPF_TAG_ET_OFFSET      0x7
#define HW_ATL2_RPF_TAG_VLAN_OFFSET    0xA
#define HW_ATL2_RPF_TAG_UNTAG_OFFSET   0xE
#define HW_ATL2_RPF_TAG_L3_V4_OFFSET   0xF
#define HW_ATL2_RPF_TAG_L3_V6_OFFSET   0x12
#define HW_ATL2_RPF_TAG_L4_OFFSET      0x15
#define HW_ATL2_RPF_TAG_L4_FLEX_OFFSET 0x18
#define HW_ATL2_RPF_TAG_FLEX_OFFSET    0x1B
#define HW_ATL2_RPF_TAG_PCP_OFFSET     0x1D

#define HW_ATL2_RPF_TAG_UC_MASK    (0x0000003F << HW_ATL2_RPF_TAG_UC_OFFSET)
#define HW_ATL2_RPF_TAG_ALLMC_MASK (0x00000001 << HW_ATL2_RPF_TAG_ALLMC_OFFSET)
#define HW_ATL2_RPF_TAG_UNTAG_MASK (0x00000001 << HW_ATL2_RPF_TAG_UNTAG_OFFSET)
#define HW_ATL2_RPF_TAG_VLAN_MASK  (0x0000000F << HW_ATL2_RPF_TAG_VLAN_OFFSET)
#define HW_ATL2_RPF_TAG_ET_MASK    (0x00000007 << HW_ATL2_RPF_TAG_ET_OFFSET)
#define HW_ATL2_RPF_TAG_L3_V4_MASK (0x00000007 << HW_ATL2_RPF_TAG_L3_V4_OFFSET)
#define HW_ATL2_RPF_TAG_L3_V6_MASK (0x00000007 << HW_ATL2_RPF_TAG_L3_V6_OFFSET)
#define HW_ATL2_RPF_TAG_L4_MASK    (0x00000007 << HW_ATL2_RPF_TAG_L4_OFFSET)
#define HW_ATL2_RPF_TAG_PCP_MASK   (0x00000007 << HW_ATL2_RPF_TAG_PCP_OFFSET)

#define HW_ATL2_RPF_TAG_BC         1
#define HW_ATL2_RPF_TAG_BASE_UC    2

enum HW_ATL2_RPF_ART_INDEX {
	HW_ATL2_RPF_L2_PROMISC_OFF_INDEX,
	HW_ATL2_RPF_VLAN_PROMISC_OFF_INDEX,
	HW_ATL2_RPF_L3L4_USER_INDEX	= 8,
	HW_ATL2_RPF_ET_PCP_USER_INDEX	= HW_ATL2_RPF_L3L4_USER_INDEX + 16,
	HW_ATL2_RPF_VLAN_USER_INDEX	= HW_ATL2_RPF_ET_PCP_USER_INDEX + 16,
	HW_ATL2_RPF_PCP_TO_TC_INDEX	= HW_ATL2_RPF_VLAN_USER_INDEX +
					  HW_ATL_VLAN_MAX_FILTERS,
};

#define HW_ATL2_RPF_L3_CMD_EN       BIT(0)
#define HW_ATL2_RPF_L3_CMD_SA_EN    BIT(1)
#define HW_ATL2_RPF_L3_CMD_DA_EN    BIT(2)
#define HW_ATL2_RPF_L3_CMD_PROTO_EN BIT(3)

#define HW_ATL2_RPF_L3_V6_CMD_EN       BIT(0x10)
#define HW_ATL2_RPF_L3_V6_CMD_SA_EN    BIT(0x11)
#define HW_ATL2_RPF_L3_V6_CMD_DA_EN    BIT(0x12)
#define HW_ATL2_RPF_L3_V6_CMD_PROTO_EN BIT(0x13)

#define HW_ATL2_RPF_L4_CMD_EN       BIT(0)
#define HW_ATL2_RPF_L4_CMD_DP_EN    BIT(1)
#define HW_ATL2_RPF_L4_CMD_SP_EN    BIT(2)

#define HW_ATL2_ACTION(ACTION, RSS, INDEX, VALID) \
	((((ACTION) & 0x3U) << 8) | \
	(((RSS) & 0x1U) << 7) | \
	(((INDEX) & 0x3FU) << 2) | \
	(((VALID) & 0x1U) << 0))

#define HW_ATL2_ACTION_DROP HW_ATL2_ACTION(0, 0, 0, 1)
#define HW_ATL2_ACTION_DISABLE HW_ATL2_ACTION(0, 0, 0, 0)
#define HW_ATL2_ACTION_ASSIGN_QUEUE(QUEUE) HW_ATL2_ACTION(1, 0, (QUEUE), 1)
#define HW_ATL2_ACTION_ASSIGN_TC(TC) HW_ATL2_ACTION(1, 1, (TC), 1)

#define HW_ATL2_RPF_L3L4_FILTERS 8
#define HW_ATL2_RPF_L3V4_FILTERS 8
#define HW_ATL2_RPF_L3V6_FILTERS 6
#define HW_ATL2_RPF_L4_FILTERS 8
#define HW_ATL2_RPF_VLAN_FILTERS 16
#define HW_ATL2_RPF_ETYPE_FILTERS 16
#define HW_ATL2_RPF_ETYPE_TAGS 7

enum HW_ATL2_RPF_RSS_HASH_TYPE {
	HW_ATL2_RPF_RSS_HASH_TYPE_NONE = 0,
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV4 = BIT(0),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV4_TCP = BIT(1),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV4_UDP = BIT(2),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV6 = BIT(3),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_TCP = BIT(4),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_UDP = BIT(5),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_EX = BIT(6),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_EX_TCP = BIT(7),
	HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_EX_UDP = BIT(8),
	HW_ATL2_RPF_RSS_HASH_TYPE_ALL = HW_ATL2_RPF_RSS_HASH_TYPE_IPV4 |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV4_TCP |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV4_UDP |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV6 |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_TCP |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_UDP |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_EX |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_EX_TCP |
					HW_ATL2_RPF_RSS_HASH_TYPE_IPV6_EX_UDP,
};

#define HW_ATL_MCAST_FLT_ANY_TO_HOST 0x00010FFFU

struct hw_atl2_l3_filter {
	u8 proto;
	u8 usage;
	u32 cmd;
	u32 srcip[4];
	u32 dstip[4];
};

struct hw_atl2_l4_filter {
	u8 usage;
	u32 cmd;
	u16 sport;
	u16 dport;
};

struct hw_atl2_l3l4_filter {
	s8 l3_index;
	s8 l4_index;
	u8 ipv6;
};

struct hw_atl2_active_filters_l3 {
	u8 active_ipv4;
	u8 active_ipv6;
};

struct hw_atl2_tag_policy {
	u16 action;
	u16 usage;
};

/** Find tag with the same action or new free tag
 *  top - top inclusive tag value
 *  action - action for ActionResolverTable
 */
static inline int hw_atl2_filter_tag_get(struct hw_atl2_tag_policy *tags,
					 int top, u16 action)
{
	int i;

	for (i = 1; i <= top; i++)
		if ((tags[i].usage > 0) && (tags[i].action == action)) {
			tags[i].usage++;
			return i;
		}

	for (i = 1; i <= top; i++)
		if (tags[i].usage == 0) {
			tags[i].usage = 1;
			tags[i].action = action;
			return i;
		}

	return -1;
}

static inline void hw_atl2_filter_tag_put(struct hw_atl2_tag_policy *tags,
					  int tag)
{
	if (tags[tag].usage > 0)
		tags[tag].usage--;
}

struct hw_atl2_priv {
	struct hw_atl2_l3_filter l3_v4_filters[HW_ATL2_RPF_L3L4_FILTERS];
	struct hw_atl2_l3_filter l3_v6_filters[HW_ATL2_RPF_L3L4_FILTERS];
	struct hw_atl2_l4_filter l4_filters[HW_ATL2_RPF_L3L4_FILTERS];
	struct hw_atl2_l3l4_filter l3l4_filters[HW_ATL2_RPF_L3L4_FILTERS];
	struct hw_atl2_tag_policy etype_policy[HW_ATL2_RPF_ETYPE_FILTERS];
	struct hw_atl2_active_filters_l3 l3_active_filters;
	struct statistics_s last_stats;
	u32 cable_diag_tid1;
	unsigned int art_base_index;
	unsigned int art_count;
	unsigned int l2_filters_base_index;
	unsigned int l2_filter_count;
	unsigned int etype_filter_base_index;
	unsigned int etype_filter_count;
	unsigned int etype_filter_tag_top;
	unsigned int vlan_filter_base_index;
	unsigned int vlan_filter_count;
	unsigned int l3_v4_filter_base_index;
	unsigned int l3_v4_filter_count;
	unsigned int l3_v6_filter_base_index;
	unsigned int l3_v6_filter_count;
	unsigned int l4_filter_base_index;
	unsigned int l4_filter_count;
};

#endif /* HW_ATL2_INTERNAL_H */
