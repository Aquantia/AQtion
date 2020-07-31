// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 * Copyright (C) 2020 Marvell International Ltd.
 */

/* File hw_atl2_llh.c: Definitions of bitfield and register access functions for
 * Atlantic registers.
 */

#include "hw_atl2_llh.h"
#include "hw_atl2_llh_internal.h"
#include "aq_hw_utils.h"

void hw_atl2_phi_ext_tag_set(struct aq_hw_s *aq_hw, u32 val)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_PHI_EXT_TAG_EN_ADR,
			    HW_ATL2_PHI_EXT_TAG_EN_MSK,
			    HW_ATL2_PHI_EXT_TAG_EN_SHIFT, val);
}

u32 hw_atl2_phi_ext_tag_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw, HW_ATL2_PHI_EXT_TAG_EN_ADR,
				  HW_ATL2_PHI_EXT_TAG_EN_MSK,
				  HW_ATL2_PHI_EXT_TAG_EN_SHIFT);
}

void hw_atl2_rpf_redirection_table2_select_set(struct aq_hw_s *aq_hw,
					       u32 select)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_ADR,
			    HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_MSK,
			    HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_SHIFT, select);
}

void hw_atl2_rpf_rss_hash_type_set(struct aq_hw_s *aq_hw, u32 rss_hash_type)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_ADR,
			    HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_MSK,
			    HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_SHIFT,
			    rss_hash_type);
}

u32 hw_atl2_rpf_rss_hash_type_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_ADR,
				  HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_MSK,
				  HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_SHIFT);
}

/* rpf */

void hw_atl2_rpf_new_enable_set(struct aq_hw_s *aq_hw, u32 enable)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_NEW_EN_ADR,
			    HW_ATL2_RPF_NEW_EN_MSK,
			    HW_ATL2_RPF_NEW_EN_SHIFT,
			    enable);
}

void hw_atl2_rpfl2_uc_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPFL2UC_TAG_ADR(filter),
			    HW_ATL2_RPFL2UC_TAG_MSK,
			    HW_ATL2_RPFL2UC_TAG_SHIFT,
			    tag);
}

void hw_atl2_rpfl2_bc_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L2_BC_TAG_ADR,
			    HW_ATL2_RPF_L2_BC_TAG_MSK,
			    HW_ATL2_RPF_L2_BC_TAG_SHIFT,
			    tag);
}

u32 hw_atl2_new_rpf_rss_redir_get(struct aq_hw_s *aq_hw, u32 tc, u32 index)
{
	return aq_hw_read_reg_bit(aq_hw, HW_ATL2_RPF_RSS_REDIR_ADR(tc, index),
				  HW_ATL2_RPF_RSS_REDIR_MSK(tc),
				  HW_ATL2_RPF_RSS_REDIR_SHIFT(tc));
}

void hw_atl2_new_rpf_rss_redir_set(struct aq_hw_s *aq_hw, u32 tc, u32 index,
				   u32 queue)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_RSS_REDIR_ADR(tc, index),
			    HW_ATL2_RPF_RSS_REDIR_MSK(tc),
			    HW_ATL2_RPF_RSS_REDIR_SHIFT(tc),
			    queue);
}

void hw_atl2_rpf_vlan_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_VL_TAG_ADR(filter),
			    HW_ATL2_RPF_VL_TAG_MSK,
			    HW_ATL2_RPF_VL_TAG_SHIFT,
			    tag);
}

void hw_atl2_rpf_etht_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_ET_TAG_ADR(filter),
			    HW_ATL2_RPF_ET_TAG_MSK,
			    HW_ATL2_RPF_ET_TAG_SHIFT, tag);
}

u32 hw_atl2_rpf_etht_flr_tag_get(struct aq_hw_s *aq_hw, u32 filter)
{
	return aq_hw_read_reg_bit(aq_hw, HW_ATL2_RPF_ET_TAG_ADR(filter),
				  HW_ATL2_RPF_ET_TAG_MSK,
				  HW_ATL2_RPF_ET_TAG_SHIFT);
}

void hw_atl2_rpf_l3_l4_enf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_L4_ENF_ADR(filter),
			    HW_ATL2_RPF_L3_L4_ENF_MSK,
			    HW_ATL2_RPF_L3_L4_ENF_SHIFT, val);
}

void hw_atl2_rpf_l3_v6_enf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_V6_ENF_ADR(filter),
			    HW_ATL2_RPF_L3_V6_ENF_MSK,
			    HW_ATL2_RPF_L3_V6_ENF_SHIFT, val);
}

void hw_atl2_rpf_l3_saf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_SAF_EN_ADR(filter),
			    HW_ATL2_RPF_L3_SAF_EN_MSK,
			    HW_ATL2_RPF_L3_SAF_EN_SHIFT, val);
}

void hw_atl2_rpf_l3_daf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_DAF_EN_ADR(filter),
			    HW_ATL2_RPF_L3_DAF_EN_MSK,
			    HW_ATL2_RPF_L3_DAF_EN_SHIFT, val);
}

void hw_atl2_rpf_l4_spf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L4_SPF_EN_ADR(filter),
			    HW_ATL2_RPF_L4_SPF_EN_MSK,
			    HW_ATL2_RPF_L4_SPF_EN_SHIFT, val);
}

void hw_atl2_rpf_l4_dpf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L4_DPF_EN_ADR(filter),
			    HW_ATL2_RPF_L4_DPF_EN_MSK,
			    HW_ATL2_RPF_L4_DPF_EN_SHIFT, val);
}

void hw_atl2_rpf_l4_protf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L4_PROTF_EN_ADR(filter),
			    HW_ATL2_RPF_L4_PROTF_EN_MSK,
			    HW_ATL2_RPF_L4_PROTF_EN_SHIFT, val);
}

void hw_atl2_rpf_l3_arpf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_ARPF_EN_ADR(filter),
			    HW_ATL2_RPF_L3_ARPF_EN_MSK,
			    HW_ATL2_RPF_L3_ARPF_EN_SHIFT, val);
}

void hw_atl2_rpf_l3_l4_rxqf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_L4_RXQF_EN_ADR(filter),
			    HW_ATL2_RPF_L3_L4_RXQF_EN_MSK,
			    HW_ATL2_RPF_L3_L4_RXQF_EN_SHIFT, val);
}

void hw_atl2_rpf_l3_l4_mng_rxqf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_L4_MNG_RXQF_ADR(filter),
			    HW_ATL2_RPF_L3_L4_MNG_RXQF_MSK,
			    HW_ATL2_RPF_L3_L4_MNG_RXQF_SHIFT, val);
}

void hw_atl2_rpf_l3_l4_actf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_L4_ACTF_ADR(filter),
			    HW_ATL2_RPF_L3_L4_ACTF_MSK,
			    HW_ATL2_RPF_L3_L4_ACTF_SHIFT, val);
}

void hw_atl2_rpf_l3_l4_rxqf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_L4_RXQF_ADR(filter),
			    HW_ATL2_RPF_L3_L4_RXQF_MSK,
			    HW_ATL2_RPF_L3_L4_RXQF_SHIFT, val);
}

void hw_atl2_rpf_l3_v4_dest_addr_set(struct aq_hw_s *aq_hw, u32 filter, u32 val)
{
	u32 addr_set = 6 + ((filter < 4) ? 0 : 1);
	u32 dword = filter % 4;

	aq_hw_write_reg(aq_hw, HW_ATL2_RPF_L3_DA_DW_ADR(addr_set, dword), val);
}

void hw_atl2_rpf_l3_v4_src_addr_set(struct aq_hw_s *aq_hw, u32 filter, u32 val)
{
	u32 addr_set = 6 + ((filter < 4) ? 0 : 1);
	u32 dword = filter % 4;

	aq_hw_write_reg(aq_hw, HW_ATL2_RPF_L3_SA_DW_ADR(addr_set, dword), val);
}

void hw_atl2_rpf_l3_v6_dest_addr_set(struct aq_hw_s *aq_hw, u8 location,
				     u32 *ipv6_dst)
{
	int i;

	for (i = 0; i < 4; ++i)
		aq_hw_write_reg(aq_hw,
				HW_ATL2_RPF_L3_DA_DW_ADR(location, 3 - i),
				ipv6_dst[i]);
}

void hw_atl2_rpf_l3_v6_src_addr_set(struct aq_hw_s *aq_hw, u8 location,
				    u32 *ipv6_src)
{
	int i;

	for (i = 0; i < 4; ++i)
		aq_hw_write_reg(aq_hw,
				HW_ATL2_RPF_L3_SA_DW_ADR(location, 3 - i),
				ipv6_src[i]);
}

void hw_atl2_rpf_l3_v4_cmd_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_V4_CMD_ADR(filter),
			    HW_ATL2_RPF_L3_V4_CMD_MSK,
			    HW_ATL2_RPF_L3_V4_CMD_SHIFT, val);
}

void hw_atl2_rpf_l3_v6_cmd_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_V6_CMD_ADR(filter),
			    HW_ATL2_RPF_L3_V6_CMD_MSK,
			    HW_ATL2_RPF_L3_V6_CMD_SHIFT, val);
}

void hw_atl2_rpf_l3_v6_v4_select_set(struct aq_hw_s *aq_hw, u32 val)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_V6_V4_SELECT_ADR,
			    HW_ATL2_RPF_L3_V6_V4_SELECT_MSK,
			    HW_ATL2_RPF_L3_V6_V4_SELECT_SHIFT, val);
}

void hw_atl2_rpf_l3_v4_tag_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_V4_TAG_ADR(filter),
			    HW_ATL2_RPF_L3_V4_TAG_MSK,
			    HW_ATL2_RPF_L3_V4_TAG_SHIFT, val);
}

void hw_atl2_rpf_l3_v6_tag_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L3_V6_TAG_ADR(filter),
			    HW_ATL2_RPF_L3_V6_TAG_MSK,
			    HW_ATL2_RPF_L3_V6_TAG_SHIFT, val);
}

void hw_atl2_rpf_l4_tag_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L4_TAG_ADR(filter),
			    HW_ATL2_RPF_L4_TAG_MSK,
			    HW_ATL2_RPF_L4_TAG_SHIFT, val);
}
void hw_atl2_rpf_l4_cmd_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L4_CMD_ADR(filter),
			    HW_ATL2_RPF_L4_CMD_MSK,
			    HW_ATL2_RPF_L4_CMD_SHIFT, val);
}

void hw_atl2_rpf_l4_protf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_L4_PROTF_ADR(filter),
			    HW_ATL2_RPF_L4_PROTF_MSK,
			    HW_ATL2_RPF_L4_PROTF_SHIFT, val);
}

/* tsg */
static inline void _hw_atl2_clock_modif_value_set(struct aq_hw_s *aq_hw,
						  u32 clock_sel, u64 ns)
{
	aq_hw_write_reg64(aq_hw,
			  HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_MODIF_VAL_LSW),
			  ns);
}

void hw_atl2_tsg_clock_en(struct aq_hw_s *aq_hw,
			  u32 clock_sel, u32 clock_enable)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_CFG),
			    HW_ATL2_TSG_CLOCK_EN_MSK,
			    HW_ATL2_TSG_CLOCK_EN_SHIFT,
			    clock_enable);
}

void hw_atl2_tsg_clock_reset(struct aq_hw_s *aq_hw, u32 clock_sel)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_CFG),
			    HW_ATL2_TSG_SYNC_RESET_MSK,
			    HW_ATL2_TSG_SYNC_RESET_SHIFT, 1);
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_CFG),
			    HW_ATL2_TSG_SYNC_RESET_MSK,
			    HW_ATL2_TSG_SYNC_RESET_SHIFT, 0);
}

u64 hw_atl2_tsg_clock_read(struct aq_hw_s *aq_hw, u32 clock_sel)
{
	return aq_hw_read_reg64(aq_hw,
				HW_ATL2_TSG_REG_ADR(clock_sel,
						    READ_CUR_NS_LSW));
}

void hw_atl2_tsg_clock_set(struct aq_hw_s *aq_hw, u32 clock_sel, u64 ns,
			   u32 fns)
{
	_hw_atl2_clock_modif_value_set(aq_hw, clock_sel, ns);
	aq_hw_write_reg(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_MODIF_CTRL),
			HW_ATL2_TSG_SET_COUNTER_MSK);
}

void hw_atl2_tsg_clock_add(struct aq_hw_s *aq_hw, u32 clock_sel, u64 ns,
			   u32 fns)
{
	_hw_atl2_clock_modif_value_set(aq_hw, clock_sel, ns);
	aq_hw_write_reg(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_MODIF_CTRL),
			HW_ATL2_TSG_ADD_COUNTER_MSK);
}

void hw_atl2_tsg_clock_sub(struct aq_hw_s *aq_hw, u32 clock_sel, u64 ns,
			   u32 fns)
{
	_hw_atl2_clock_modif_value_set(aq_hw, clock_sel, ns);
	aq_hw_write_reg(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_MODIF_CTRL),
			HW_ATL2_TSG_SUBTRACT_COUNTER_MSK);
}

void hw_atl2_tsg_clock_increment_set(struct aq_hw_s *aq_hw,
				     u32 clock_sel, u32 ns, u32 fns)
{
	u32 nsfns = (ns & 0xff) | (fns & 0xffffff00);

	aq_hw_write_reg(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_INC_CFG),
			nsfns);
	aq_hw_write_reg(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, CLOCK_MODIF_CTRL),
			HW_ATL2_TSG_LOAD_INC_CFG_MSK);
}

void  hw_atl2_fpga_tsg_gpio_input_set(struct aq_hw_s *aq_hw, u32 clock_sel)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG_SPARE_WRITE_REG_ADR,
		HW_ATL2_TSG_SPARE_FPGA_GPIO_CTRL_MSK,
		HW_ATL2_TSG_SPARE_FPGA_GPIO_CTRL_SHIFT,
		clock_sel == 1 ? HW_ATL2_TSG_SPARE_FPGA_TSG1_GPIO_TS_I :
			HW_ATL2_TSG_SPARE_FPGA_TSG0_GPIO_TS_I);
}

void hw_atl2_tsg_gpio_input_set(struct aq_hw_s *aq_hw, int on, u32 pin,
				u32 clock_sel)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG_REG_ADR(clock_sel, GPIO_CFG),
			    HW_ATL2_TSG_GPIO_IN_MODE_MSK,
			    HW_ATL2_TSG_GPIO_IN_MONITOR_EN_SHIFT,
			    !!on ? HW_ATL2_TSG_GPIO_IN_MONITOR_EN_MSK |
				(HW_ATL2_TSG_GPIO_IN_MODE_POSEDGE <<
					HW_ATL2_TSG_GPIO_IN_MODE_SHIFT) :
				0);
}

void hw_atl2_tsg_ext_isr_to_host_set(struct aq_hw_s *aq_hw, int on)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_GLB_CONTROL_2_ADR,
			    HW_ATL2_MIF_INTERRUPT_2_TO_ITR_MSK,
			    HW_ATL2_MIF_INTERRUPT_TO_ITR_SHIFT + 2,
			    !!on);
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_GLB_CONTROL_2_ADR,
			    HW_ATL2_EN_INTERRUPT_MIF2_TO_ITR_MSK,
			    HW_ATL2_EN_INTERRUPT_TO_ITR_SHIFT + 2,
			    !!on);
}

void hw_atl2_tpb_tps_highest_priority_tc_enable_set(struct aq_hw_s *aq_hw,
			u32 tps_highest_prio_tc_en)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_ADR,
			    HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_MSK,
			    HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_SHIFT,
			    tps_highest_prio_tc_en);
}

void hw_atl2_tpb_tps_highest_priority_tc_set(struct aq_hw_s *aq_hw,
			u32 tps_highest_prio_tc)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPB_HIGHEST_PRIO_TC_ADR,
			    HW_ATL2_TPB_HIGHEST_PRIO_TC_MSK,
			    HW_ATL2_TPB_HIGHEST_PRIO_TC_SHIFT,
			    tps_highest_prio_tc);
}

void hw_atl2_tsg_gpio_isr_to_host_set(struct aq_hw_s *aq_hw,
				      int on, u32 clock_sel)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_GLOBAL_HIGH_PRIO_INTERRUPT_1_MASK_ADR,
		clock_sel == 1 ? HW_ATL2_TSG_TSG1_GPIO_INTERRUPT_MSK :
			HW_ATL2_TSG_TSG0_GPIO_INTERRUPT_MSK,
		clock_sel == 1 ? HW_ATL2_TSG_TSG1_GPIO_INTERRUPT_SHIFT :
			HW_ATL2_TSG_TSG0_GPIO_INTERRUPT_SHIFT,
		!!on);
}

void hw_atl2_tsg_gpio_clear_status(struct aq_hw_s *aq_hw, u32 clock_sel)
{
	aq_hw_read_reg(aq_hw, HW_ATL2_GLOBAL_INTERNAL_ALARMS_1_ADR);
}

void hw_atl2_tsg_gpio_input_event_info_get(struct aq_hw_s *aq_hw,
					   u32 clock_sel,
					   u32 *event_count,
					   u64 *event_ts)
{
	if (event_count)
		*event_count = aq_hw_read_reg(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, EXT_CLK_COUNT));

	if (event_ts)
		*event_ts = aq_hw_read_reg64(aq_hw,
			HW_ATL2_TSG_REG_ADR(clock_sel, GPIO_EVENT_TS_LSW));
}

void hw_atl2_fpga_tsg_ptp_gpio_gen_pulse(struct aq_hw_s *aq_hw,
					 u32 clk_sel, u32 on)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG_SPARE_WRITE_REG_ADR,
		HW_ATL2_TSG_SPARE_FPGA_GPIO_CTRL_MSK,
		HW_ATL2_TSG_SPARE_FPGA_GPIO_CTRL_SHIFT,
		on ? (clk_sel == 1 ? HW_ATL2_TSG_SPARE_FPGA_TSG1_CLK_EVNT_O :
			HW_ATL2_TSG_SPARE_FPGA_TSG0_CLK_EVNT_O) : 0);
}

void hw_atl2_tsg_ptp_gpio_gen_pulse(struct aq_hw_s *aq_hw, u32 clk_sel,
				    u64 ts, u32 period, u32 hightime)
{
	if (ts != 0) {
		aq_hw_write_reg64(aq_hw, HW_ATL2_TSG_REG_ADR(clk_sel,
				  GPIO_EVENT_GEN_TS_LSW), ts);

		aq_hw_write_reg64(aq_hw,
			HW_ATL2_TSG_REG_ADR(clk_sel, GPIO_EVENT_HIGH_TIME_LSW),
			hightime);
		aq_hw_write_reg64(aq_hw,
			HW_ATL2_TSG_REG_ADR(clk_sel, GPIO_EVENT_LOW_TIME_LSW),
			(period - hightime));
	}

	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_TSG_REG_ADR(clk_sel, GPIO_EVENT_GEN_CFG),
			    HW_ATL2_TSG_GPIO_EVENT_MODE_MSK |
				HW_ATL2_TSG_GPIO_OUTPUT_EN_MSK |
				HW_ATL2_TSG_GPIO_GEN_OUTPUT_EN_MSK,
			   HW_ATL2_TSG_GPIO_OUTPUT_EN_SHIFT,
			   (!ts ? 0 :
				(HW_ATL2_TSG_GPIO_EVENT_MODE_SET_ON_TIME <<
					(HW_ATL2_TSG_GPIO_EVENT_MODE_SHIFT -
					HW_ATL2_TSG_GPIO_OUTPUT_EN_SHIFT)) |
				(HW_ATL2_TSG_GPIO_GEN_OUTPUT_EN_MSK) |
				(HW_ATL2_TSG_GPIO_OUTPUT_EN_MSK)));
}

void hw_atl2_rpf_rx_desc_timestamp_req_set(struct aq_hw_s *aq_hw, u32 request,
					   u32 descriptor)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_ADR(descriptor),
			    HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_MSK,
			    HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_SHIFT, request);
}

u32 hw_atl2_rpf_rx_desc_timestamp_req_get(struct aq_hw_s *aq_hw, u32 descriptor)
{
	u32 reg = HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_ADR(descriptor);

	return aq_hw_read_reg_bit(aq_hw, reg,
				  HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_MSK,
				  HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_SHIFT);
}

/* TX */

void hw_atl2_tpb_tx_tc_q_rand_map_en_set(struct aq_hw_s *aq_hw,
					 const u32 tc_q_rand_map_en)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_ADR,
			    HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_MSK,
			    HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_SHIFT,
			    tc_q_rand_map_en);
}

void hw_atl2_tpb_tx_buf_clk_gate_en_set(struct aq_hw_s *aq_hw, u32 clk_gate_en)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_ADR,
			    HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_MSK,
			    HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_SHIFT,
			    clk_gate_en);
}

void hw_atl2_reg_tx_intr_moder_ctrl_set(struct aq_hw_s *aq_hw,
					u32 tx_intr_moderation_ctl,
					u32 queue)
{
	aq_hw_write_reg(aq_hw, HW_ATL2_TX_INTR_MODERATION_CTL_ADR(queue),
			tx_intr_moderation_ctl);
}

void hw_atl2_tdm_tx_desc_timestamp_writeback_en_set(struct aq_hw_s *aq_hw,
						    u32 enable, u32 descriptor)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TDM_DESCD_TS_WRB_EN_ADR(descriptor),
			    HW_ATL2_TDM_DESCD_TS_WRB_EN_MSK,
			    HW_ATL2_TDM_DESCD_TS_WRB_EN_SHIFT, enable);
}

u32 hw_atl2_tdm_tx_desc_timestamp_writeback_en_get(struct aq_hw_s *aq_hw,
						   u32 descriptor)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_TDM_DESCD_TS_WRB_EN_ADR(descriptor),
				  HW_ATL2_TDM_DESCD_TS_WRB_EN_MSK,
				  HW_ATL2_TDM_DESCD_TS_WRB_EN_SHIFT);
}

void hw_atl2_tdm_tx_desc_timestamp_en_set(struct aq_hw_s *aq_hw, u32 enable,
					  u32 descriptor)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TDM_DESCD_TS_EN_ADR(descriptor),
			    HW_ATL2_TDM_DESCD_TS_EN_MSK,
			    HW_ATL2_TDM_DESCD_TS_EN_SHIFT, enable);
}

u32 hw_atl2_tdm_tx_desc_timestamp_en_get(struct aq_hw_s *aq_hw, u32 descriptor)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_TDM_DESCD_TS_EN_ADR(descriptor),
				  HW_ATL2_TDM_DESCD_TS_EN_MSK,
				  HW_ATL2_TDM_DESCD_TS_EN_SHIFT);
}

void hw_atl2_tdm_tx_desc_avb_en_set(struct aq_hw_s *aq_hw, u32 enable,
				    u32 descriptor)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TDM_DESCD_AVB_EN_ADR(descriptor),
			    HW_ATL2_TDM_DESCD_AVB_EN_MSK,
			    HW_ATL2_TDM_DESCD_AVB_EN_SHIFT, enable);
}

u32 hw_atl2_tdm_tx_desc_avb_en_get(struct aq_hw_s *aq_hw, u32 descriptor)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_TDM_DESCD_AVB_EN_ADR(descriptor),
				  HW_ATL2_TDM_DESCD_AVB_EN_MSK,
				  HW_ATL2_TDM_DESCD_AVB_EN_SHIFT);
}

void hw_atl2_tps_tx_pkt_shed_data_arb_mode_set(struct aq_hw_s *aq_hw,
					       const u32 data_arb_mode)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPS_DATA_TC_ARB_MODE_ADR,
			    HW_ATL2_TPS_DATA_TC_ARB_MODE_MSK,
			    HW_ATL2_TPS_DATA_TC_ARB_MODE_SHIFT,
			    data_arb_mode);
}

void hw_atl2_tps_tx_pkt_shed_tc_data_max_credit_set(struct aq_hw_s *aq_hw,
						    const u32 tc,
						    const u32 max_credit)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPS_DATA_TCTCREDIT_MAX_ADR(tc),
			    HW_ATL2_TPS_DATA_TCTCREDIT_MAX_MSK,
			    HW_ATL2_TPS_DATA_TCTCREDIT_MAX_SHIFT,
			    max_credit);
}

void hw_atl2_tps_tx_pkt_shed_tc_data_weight_set(struct aq_hw_s *aq_hw,
						const u32 tc,
						const u32 weight)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TPS_DATA_TCTWEIGHT_ADR(tc),
			    HW_ATL2_TPS_DATA_TCTWEIGHT_MSK,
			    HW_ATL2_TPS_DATA_TCTWEIGHT_SHIFT,
			    weight);
}

void _hw_atl2_tsg_ptp_gpio_en_pulse(struct aq_hw_s *aq_hw, u32 clk_sel, bool en)
{
	/* Enable GPIO and set "GTorEQ" mode */
	u32 val = en ? (2 << HW_ATL2_TSG0_CLOCKEVENTOUTPUTMODE_SHIFT) | 1 : 0;

	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSGPTPGPIOCTRL_ADR,
		clk_sel == 1 ?
			HW_ATL2_TSG1_CLOCKEVENTOUTPUTMODE_MSK |
				HW_ATL2_TSG1_ENCLOCKEVENTOUTPUT_MSK :
			HW_ATL2_TSG0_CLOCKEVENTOUTPUTMODE_MSK |
				HW_ATL2_TSG0_ENCLOCKEVENTOUTPUT_MSK,
		clk_sel == 1 ?
			HW_ATL2_TSG1_ENCLOCKEVENTOUTPUT_SHIFT :
			HW_ATL2_TSG0_ENCLOCKEVENTOUTPUT_SHIFT,
		val);
}

void _hw_atl2_tsg_ptp_gpio_ts(struct aq_hw_s *aq_hw, u32 clk_sel, u64 ts)
{
	aq_hw_write_reg(aq_hw, clk_sel == 1 ?
			HW_ATL2_MODIFY_TSG1_NS_COUNTER_VAL0_ADR :
			HW_ATL2_MODIFY_TSG0_NS_COUNTER_VAL0_ADR,
			ts & 0xffffffff);
	aq_hw_write_reg(aq_hw, clk_sel == 1 ?
			HW_ATL2_MODIFY_TSG1_NS_COUNTER_VAL1_ADR :
			HW_ATL2_MODIFY_TSG0_NS_COUNTER_VAL1_ADR,
			(ts >> 32) & 0xffffffff);
}

void hw_atl2_tdm_tx_data_read_req_limit_set(struct aq_hw_s *aq_hw, u32 limit)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_ADR,
			    HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_MSK,
			    HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_SHIFT, limit);
}

void hw_atl2_tdm_tx_desc_read_req_limit_set(struct aq_hw_s *aq_hw, u32 limit)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_ADR,
			    HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_MSK,
			    HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_SHIFT, limit);
}

u32 hw_atl2_get_hw_version(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg(aq_hw, HW_ATL2_FPGA_VER_ADR);
}

void hw_atl2_init_launchtime(struct aq_hw_s *aq_hw)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_LT_CTRL_ADR,
			    HW_ATL2_LT_CTRL_CLK_RATIO_MSK,
			    HW_ATL2_LT_CTRL_CLK_RATIO_SHIFT,
			    HW_ATL2_LT_CTRL_CLK_RATIO_FULL_SPEED);
}

/* set action resolver record */
void hw_atl2_rpf_act_rslvr_record_set(struct aq_hw_s *aq_hw, u8 location,
				      u32 tag, u32 mask, u32 action)
{
	aq_hw_write_reg(aq_hw,
			HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_ADR(location),
			tag);
	aq_hw_write_reg(aq_hw,
			HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_ADR(location),
			mask);
	aq_hw_write_reg(aq_hw,
			HW_ATL2_RPF_ACT_RSLVR_ACTN_ADR(location),
			action);
}

/* get action resolver tag record */
void hw_atl2_rpf_act_rslvr_record_get(struct aq_hw_s *aq_hw, u8 location,
				      u32 *tag, u32 *mask, u32 *action)
{
	*tag = aq_hw_read_reg(aq_hw,
			      HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_ADR(location));
	*mask = aq_hw_read_reg(aq_hw,
			       HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_ADR(location));
	*action = aq_hw_read_reg(aq_hw,
				 HW_ATL2_RPF_ACT_RSLVR_ACTN_ADR(location));
}

void hw_atl2_rpf_act_rslvr_section_en_set(struct aq_hw_s *aq_hw, u32 sections)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_RPF_REC_TAB_EN_ADR,
			    HW_ATL2_RPF_REC_TAB_EN_MSK,
			    HW_ATL2_RPF_REC_TAB_EN_SHIFT,
			    sections);
}

u32 hw_atl2_rpf_act_rslvr_section_en_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw, HW_ATL2_RPF_REC_TAB_EN_ADR,
				   HW_ATL2_RPF_REC_TAB_EN_MSK,
				   HW_ATL2_RPF_REC_TAB_EN_SHIFT);
}

void hw_atl2_mif_shared_buf_get(struct aq_hw_s *aq_hw, int offset, u32 *data,
				int len)
{
	int j = 0;
	int i;

	for (i = offset; i < offset + len; i++, j++)
		data[j] = aq_hw_read_reg(aq_hw,
					 HW_ATL2_MIF_SHARED_BUFFER_IN_ADR(i));
}

void hw_atl2_mif_shared_buf_write(struct aq_hw_s *aq_hw, int offset, u32 *data,
				  int len)
{
	int j = 0;
	int i;

	for (i = offset; i < offset + len; i++, j++)
		aq_hw_write_reg(aq_hw, HW_ATL2_MIF_SHARED_BUFFER_IN_ADR(i),
				data[j]);
}

void hw_atl2_mif_shared_buf_read(struct aq_hw_s *aq_hw, int offset, u32 *data,
				 int len)
{
	int j = 0;
	int i;

	for (i = offset; i < offset + len; i++, j++)
		data[j] = aq_hw_read_reg(aq_hw,
					 HW_ATL2_MIF_SHARED_BUFFER_OUT_ADR(i));
}

void hw_atl2_mif_host_finished_write_set(struct aq_hw_s *aq_hw, u32 finish)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_MIF_HOST_FINISHED_WRITE_ADR,
			    HW_ATL2_MIF_HOST_FINISHED_WRITE_MSK,
			    HW_ATL2_MIF_HOST_FINISHED_WRITE_SHIFT,
			    finish);
}

u32 hw_atl2_mif_mcp_finished_read_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw, HW_ATL2_MIF_MCP_FINISHED_READ_ADR,
				  HW_ATL2_MIF_MCP_FINISHED_READ_MSK,
				  HW_ATL2_MIF_MCP_FINISHED_READ_SHIFT);
}

u32 hw_atl2_mif_mcp_boot_reg_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg(aq_hw, HW_ATL2_MIF_BOOT_REG_ADR);
}

void hw_atl2_mif_mcp_boot_reg_set(struct aq_hw_s *aq_hw, u32 val)
{
	return aq_hw_write_reg(aq_hw, HW_ATL2_MIF_BOOT_REG_ADR, val);
}

u32 hw_atl2_mif_host_req_int_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg(aq_hw, HW_ATL2_MCP_HOST_REQ_INT_ADR);
}

void hw_atl2_mif_host_req_int_clr(struct aq_hw_s *aq_hw, u32 val)
{
	return aq_hw_write_reg(aq_hw, HW_ATL2_MCP_HOST_REQ_INT_CLR_ADR,
			       val);
}

void hw_atl2_tsg1_ext_gpio_ts_input_select_set(struct aq_hw_s *aq_hw,
					       uint32_t tsg_gpio_ts_select)
{
	aq_hw_write_reg_bit(aq_hw, HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_ADR,
			    HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_MSK,
			    HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_SHIFT,
			    tsg_gpio_ts_select);
}

uint32_t hw_atl2_tsg1_ext_gpio_ts_input_select_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_ADR,
				  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_MSK,
				  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_SHIFT);
}

void hw_atl2_tsg0_ext_gpio_ts_input_select_set(struct aq_hw_s *aq_hw,
					       uint32_t gpio_ts_in_select)
{
	aq_hw_write_reg_bit(aq_hw,  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_ADR,
			    HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_MSK,
			    HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_SHIFT,
			    gpio_ts_in_select);
}

void hw_atl2_gpio_special_mode_set(struct aq_hw_s *aq_hw,
				   uint32_t gpio_special_mode,
				   uint32_t pin)
{
	aq_hw_write_reg_bit(aq_hw,  HW_ATL2_GPIO_PIN_SPEC_MODE_ADR(pin),
			    HW_ATL2_GPIO_PIN_SPEC_MODE_MSK,
			    HW_ATL2_GPIO_PIN_SPEC_MODE_SHIFT,
			    gpio_special_mode);
}

uint32_t hw_atl2_gpio_special_mode_get(struct aq_hw_s *aq_hw, uint32_t pin)
{
	return aq_hw_read_reg_bit(aq_hw, HW_ATL2_GPIO_PIN_SPEC_MODE_ADR(pin),
				  HW_ATL2_GPIO_PIN_SPEC_MODE_MSK,
				  HW_ATL2_GPIO_PIN_SPEC_MODE_SHIFT);
}

void hw_atl2_prim_ts_clk_sel_set(struct aq_hw_s *aq_hw, uint32_t clk_sel)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_ADR,
			    HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_MSK,
			    HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_SHIFT,
			    clk_sel);
}

uint32_t hw_atl2_prim_ts_clk_sel_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_ADR,
				  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_MSK,
				  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_SHIFT);
}

void hw_atl2_fifo312p5_fns_inc_val_set(struct aq_hw_s *aq_hw, uint32_t value)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_ADR,
			    HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_MSK,
			    HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_SHIFT,
			    value);
}

uint32_t hw_atl2_fifo312p5_fns_inc_val_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_ADR,
				  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_MSK,
				  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_SHIFT);
}

void hw_atl2_fifo312p5_corr_period_set(struct aq_hw_s *aq_hw, uint32_t value)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_ADR,
			    HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_MSK,
			    HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_SHIFT,
			    value);
}

uint32_t hw_atl2_fifo312p5_period_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_ADR,
				  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_MSK,
				  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_SHIFT);
}

void hw_atl2_fifo312p5_ns_inc_set(struct aq_hw_s *aq_hw, uint32_t value)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_FIFO_312P_NS_INC_VAL_ADR,
			    HW_ATL2_FIFO_312P_NS_INC_VAL_MSK,
			    HW_ATL2_FIFO_312P_NS_INC_VAL_SHIFT,
			    value);
}

uint32_t hw_atl2_fifo312p5_ns_inc_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_FIFO_312P_NS_INC_VAL_ADR,
				  HW_ATL2_FIFO_312P_NS_INC_VAL_MSK,
				  HW_ATL2_FIFO_312P_NS_INC_VAL_SHIFT);
}

void hw_atl2_fifo312p5_fns_corr_set(struct aq_hw_s *aq_hw, uint32_t value)
{
	aq_hw_write_reg_bit(aq_hw,
			    HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_ADR,
			    HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_MSK,
			    HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_SHIFT,
			    value);
}

uint32_t hw_atl2_fifo312p5_fns_corr_get(struct aq_hw_s *aq_hw)
{
	return aq_hw_read_reg_bit(aq_hw,
				  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_ADR,
				  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_MSK,
				  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_SHIFT);
}
