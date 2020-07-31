/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 * Copyright (C) 2020 Marvell International Ltd.
 */

/* File hw_atl2_llh.h: Declarations of bitfield and register access functions
 *  for Atlantic registers.
 */

#ifndef HW_ATL2_LLH_H
#define HW_ATL2_LLH_H

#include <linux/types.h>

struct aq_hw_s;

/** Set Enable usage of extended tags from 32-255. */
void hw_atl2_phi_ext_tag_set(struct aq_hw_s *aq_hw, u32 val);
/** Get Enable usage of extended tags from 32-255. */
u32 hw_atl2_phi_ext_tag_get(struct aq_hw_s *aq_hw);

/* Set TX Interrupt Moderation Control Register */
void hw_atl2_reg_tx_intr_moder_ctrl_set(struct aq_hw_s *aq_hw,
					u32 tx_intr_moderation_ctl,
					u32 queue);

/* Set Redirection Table 2 Select */
void hw_atl2_rpf_redirection_table2_select_set(struct aq_hw_s *aq_hw,
					       u32 select);

/** Set RSS HASH type */
void hw_atl2_rpf_rss_hash_type_set(struct aq_hw_s *aq_hw, u32 rss_hash_type);

/** Get RSS HASH type */
u32 hw_atl2_rpf_rss_hash_type_get(struct aq_hw_s *aq_hw);

/* set new RPF enable */
void hw_atl2_rpf_new_enable_set(struct aq_hw_s *aq_hw, u32 enable);

/* set l2 unicast filter tag */
void hw_atl2_rpfl2_uc_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag, u32 filter);

/* set l2 broadcast filter tag */
void hw_atl2_rpfl2_bc_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag);

/* get new rss redirection table */
u32 hw_atl2_new_rpf_rss_redir_get(struct aq_hw_s *aq_hw, u32 tc, u32 index);

/* set new rss redirection table */
void hw_atl2_new_rpf_rss_redir_set(struct aq_hw_s *aq_hw, u32 tc, u32 index,
				   u32 queue);

/* Set VLAN filter tag */
void hw_atl2_rpf_vlan_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag, u32 filter);

/* set ethertype filter tag */
void hw_atl2_rpf_etht_flr_tag_set(struct aq_hw_s *aq_hw, u32 tag, u32 filter);

/* get ethertype filter tag */
u32 hw_atl2_rpf_etht_flr_tag_get(struct aq_hw_s *aq_hw, u32 filter);

/* set L3/L4 filter enable */
void hw_atl2_rpf_l3_l4_enf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 IPv6 enable */
void hw_atl2_rpf_l3_v6_enf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 source address enable */
void hw_atl2_rpf_l3_saf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 destination address enable */
void hw_atl2_rpf_l3_daf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L4 source port enable */
void hw_atl2_rpf_l4_spf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L4 destination port enable */
void hw_atl2_rpf_l4_dpf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L4 protocol enable */
void hw_atl2_rpf_l4_protf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 ARP filter enable */
void hw_atl2_rpf_l3_arpf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3/L4 rx queue enable */
void hw_atl2_rpf_l3_l4_rxqf_en_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3/L4 management queue */
void hw_atl2_rpf_l3_l4_mng_rxqf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3/L4 filter action */
void hw_atl2_rpf_l3_l4_actf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3/L4 rx queue */
void hw_atl2_rpf_l3_l4_rxqf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 v4 dest address */
void hw_atl2_rpf_l3_v4_dest_addr_set(struct aq_hw_s *aq_hw,
				     u32 filter, u32 val);

/* set L3 v4 src address */
void hw_atl2_rpf_l3_v4_src_addr_set(struct aq_hw_s *aq_hw, u32 filter, u32 val);

/* set L3 v4 cmd */
void hw_atl2_rpf_l3_v4_cmd_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 v6 cmd */
void hw_atl2_rpf_l3_v6_cmd_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 v6 dest address */
void hw_atl2_rpf_l3_v6_dest_addr_set(struct aq_hw_s *aq_hw, u8 location,
				     u32 *ipv6_dst);

/* set L3 v6 src address */
void hw_atl2_rpf_l3_v6_src_addr_set(struct aq_hw_s *aq_hw, u8 location,
				    u32 *ipv6_src);

/* set L3 v6 v4 select */
void hw_atl2_rpf_l3_v6_v4_select_set(struct aq_hw_s *aq_hw, u32 val);

/* set L3 v4 tag */
void hw_atl2_rpf_l3_v4_tag_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L3 v6 tag */
void hw_atl2_rpf_l3_v6_tag_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L4 cmd */
void hw_atl2_rpf_l4_cmd_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L4 tag */
void hw_atl2_rpf_l4_tag_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set L4 protocol value */
void hw_atl2_rpf_l4_protf_set(struct aq_hw_s *aq_hw, u32 val, u32 filter);

/* set tx random TC-queue mapping enable bit */
void hw_atl2_tpb_tx_tc_q_rand_map_en_set(struct aq_hw_s *aq_hw,
					 const u32 tc_q_rand_map_en);

void hw_atl2_tpb_tps_highest_priority_tc_enable_set(struct aq_hw_s *aq_hw,
	u32 tps_highest_prio_tc_en);

void hw_atl2_tpb_tps_highest_priority_tc_set(struct aq_hw_s *aq_hw,
	u32 tps_highest_prio_tc);

/* set tx buffer clock gate enable */
void hw_atl2_tpb_tx_buf_clk_gate_en_set(struct aq_hw_s *aq_hw, u32 clk_gate_en);

/* tsg */

void hw_atl2_tsg_clock_en(struct aq_hw_s *aq_hw, u32 clock_sel,
			  u32 clock_enable);

void hw_atl2_tsg_clock_reset(struct aq_hw_s *aq_hw, u32 clock_sel);
u64 hw_atl2_tsg_clock_read(struct aq_hw_s *aq_hw, u32 clock_sel);
void hw_atl2_tsg_clock_set(struct aq_hw_s *aq_hw, u32 clock_sel,
			   u64 ns, u32 fns);
void hw_atl2_tsg_clock_add(struct aq_hw_s *aq_hw, u32 clock_sel,
			   u64 ns, u32 fns);
void hw_atl2_tsg_clock_sub(struct aq_hw_s *aq_hw, u32 clock_sel,
			   u64 ns, u32 fns);

void hw_atl2_tsg_clock_increment_set(struct aq_hw_s *aq_hw, u32 clock_sel,
				     u32 ns, u32 fns);
void  hw_atl2_fpga_tsg_gpio_input_set(struct aq_hw_s *aq_hw, u32 clock_sel);
void hw_atl2_tsg_gpio_input_set(struct aq_hw_s *aq_hw, int on, u32 pin,
				u32 clock_sel);
void hw_atl2_tsg_gpio_isr_to_host_set(struct aq_hw_s *aq_hw, int on,
				      u32 clock_sel);
void hw_atl2_tsg_ext_isr_to_host_set(struct aq_hw_s *aq_hw, int on);
void hw_atl2_tsg_gpio_clear_status(struct aq_hw_s *aq_hw, u32 clock_sel);

void hw_atl2_tsg_gpio_input_event_info_get(struct aq_hw_s *aq_hw,
					   u32 clock_sel,
					   u32 *event_count,
					   u64 *event_ts);

void hw_atl2_fpga_tsg_ptp_gpio_gen_pulse(struct aq_hw_s *aq_hw,
					 u32 clk_sel, u32 on);

/** Set Rx Descriptor0 Timestamp request */
void hw_atl2_rpf_rx_desc_timestamp_req_set(struct aq_hw_s *aq_hw, u32 request,
					   u32 descriptor);

/** Get Rx Descriptor0 Timestamp request */
u32 hw_atl2_rpf_rx_desc_timestamp_req_get(struct aq_hw_s *aq_hw,
					  u32 descriptor);

/** Set Tx Descriptor Timestamp writeback Enable */
void hw_atl2_tdm_tx_desc_timestamp_writeback_en_set(struct aq_hw_s *aq_hw,
						    u32 enable,
						    u32 descriptor);

/** Get Tx Descriptor Timestamp writeback Enable */
u32 hw_atl2_tdm_tx_desc_timestamp_writeback_en_get(struct aq_hw_s *aq_hw,
						   u32 descriptor);

/** Set Tx Descriptor Timestamp enable */
void hw_atl2_tdm_tx_desc_timestamp_en_set(struct aq_hw_s *aq_hw, u32 enable,
					  u32 descriptor);

/** Get Tx Descriptor Timestamp enable */
u32 hw_atl2_tdm_tx_desc_timestamp_en_get(struct aq_hw_s *aq_hw,
					 u32 descriptor);

void hw_atl2_tps_tx_pkt_shed_data_arb_mode_set(struct aq_hw_s *aq_hw,
					       const u32 data_arb_mode);

/* set tx packet scheduler tc data max credit */
void hw_atl2_tps_tx_pkt_shed_tc_data_max_credit_set(struct aq_hw_s *aq_hw,
						    const u32 tc,
						    const u32 max_credit);

/* set tx packet scheduler tc data weight */
void hw_atl2_tps_tx_pkt_shed_tc_data_weight_set(struct aq_hw_s *aq_hw,
						const u32 tc,
						const u32 weight);

/** Set Tx Descriptor AVB enable */
void hw_atl2_tdm_tx_desc_avb_en_set(struct aq_hw_s *aq_hw, u32 enable,
				    u32 descriptor);

/** Get Tx Descriptor AVB enable */
u32 hw_atl2_tdm_tx_desc_avb_en_get(struct aq_hw_s *aq_hw, u32 descriptor);

void hw_atl2_tsg_ptp_gpio_gen_pulse(struct aq_hw_s *aq_hw, u32 clk_sel,
				    u64 ts, u32 period, u32 hightime);

void hw_atl2_tdm_tx_data_read_req_limit_set(struct aq_hw_s *aq_hw, u32 limit);

void hw_atl2_tdm_tx_desc_read_req_limit_set(struct aq_hw_s *aq_hw, u32 limit);

u32 hw_atl2_get_hw_version(struct aq_hw_s *aq_hw);

void hw_atl2_init_launchtime(struct aq_hw_s *aq_hw);

/* set action resolver record */
void hw_atl2_rpf_act_rslvr_record_set(struct aq_hw_s *aq_hw, u8 location,
				      u32 tag, u32 mask, u32 action);
/* get action resolver tag record */
void hw_atl2_rpf_act_rslvr_record_get(struct aq_hw_s *aq_hw, u8 location,
				      u32 *tag, u32 *mask, u32 *action);

/* set enable action resolver section */
void hw_atl2_rpf_act_rslvr_section_en_set(struct aq_hw_s *aq_hw, u32 sections);

/* get enable action resolver section */
u32 hw_atl2_rpf_act_rslvr_section_en_get(struct aq_hw_s *aq_hw);

/* get data from firmware shared input buffer */
void hw_atl2_mif_shared_buf_get(struct aq_hw_s *aq_hw, int offset, u32 *data,
				int len);

/* set data into firmware shared input buffer */
void hw_atl2_mif_shared_buf_write(struct aq_hw_s *aq_hw, int offset, u32 *data,
				  int len);

/* get data from firmware shared output buffer */
void hw_atl2_mif_shared_buf_read(struct aq_hw_s *aq_hw, int offset, u32 *data,
				 int len);

/* set host finished write shared buffer indication */
void hw_atl2_mif_host_finished_write_set(struct aq_hw_s *aq_hw, u32 finish);

/* get mcp finished read shared buffer indication */
u32 hw_atl2_mif_mcp_finished_read_get(struct aq_hw_s *aq_hw);

/* get mcp boot register */
u32 hw_atl2_mif_mcp_boot_reg_get(struct aq_hw_s *aq_hw);

/* set mcp boot register */
void hw_atl2_mif_mcp_boot_reg_set(struct aq_hw_s *aq_hw, u32 val);

/* get host interrupt request */
u32 hw_atl2_mif_host_req_int_get(struct aq_hw_s *aq_hw);

/* clear host interrupt request */
void hw_atl2_mif_host_req_int_clr(struct aq_hw_s *aq_hw, u32 val);

/* Set TSG EXT GPIO TS Input select */
void hw_atl2_tsg1_ext_gpio_ts_input_select_set(struct aq_hw_s *aq_hw,
					       uint32_t tsg_gpio_ts_select);

/* Get TSG EXT GPIO TS Input select */
uint32_t hw_atl2_tsg1_ext_gpio_ts_input_select_get(struct aq_hw_s *aq_hw);

/* Set PTP EXT CLK TS Input select */
void hw_atl2_tsg0_ext_clk_ts_input_select_set(struct aq_hw_s *aq_hw,
					      uint32_t clk_ts_input_select);

/* Get PTP EXT CLK TS Input select */
uint32_t hw_atl2_tsg0_ext_clk_ts_input_select_get(struct aq_hw_s *aq_hw);

/* Set PTP EXT GPIO TS Input select */
void hw_atl2_tsg0_ext_gpio_ts_input_select_set(struct aq_hw_s *aq_hw,
					       uint32_t gpio_ts_in_select);

/* Get PTP EXT GPIO TS Input select */
uint32_t hw_atl2_tsg0_ext_gpio_ts_input_select_get(struct aq_hw_s *aq_hw);

/* Set GPIO Special Mode */
void hw_atl2_gpio_special_mode_set(struct aq_hw_s *aq_hw,
				   uint32_t gpioSpecialMode, uint32_t pin);

/* Get GPIO Special Mode */
uint32_t hw_atl2_gpio_special_mode_get(struct aq_hw_s *aq_hw, uint32_t pin);

void hw_atl2_prim_ts_clk_sel_set(struct aq_hw_s *aq_hw, uint32_t clk_sel);
uint32_t hw_atl2_prim_ts_clk_sel_get(struct aq_hw_s *aq_hw);
void hw_atl2_fifo312p5_fns_inc_val_set(struct aq_hw_s *aq_hw, uint32_t clk_sel);
uint32_t hw_atl2_fifo312p5_fns_inc_val_get(struct aq_hw_s *aq_hw);
void hw_atl2_fifo312p5_corr_period_set(struct aq_hw_s *aq_hw, uint32_t clk_sel);
uint32_t hw_atl2_fifo312p5_period_get(struct aq_hw_s *aq_hw);
void hw_atl2_fifo312p5_ns_inc_set(struct aq_hw_s *aq_hw, uint32_t clk_sel);
uint32_t hw_atl2_fifo312p5_fns_corr_get(struct aq_hw_s *aq_hw);
void hw_atl2_fifo312p5_fns_corr_set(struct aq_hw_s *aq_hw, uint32_t clk_sel);
uint32_t hw_atl2_fifo312p5_ns_inc_get(struct aq_hw_s *aq_hw);


#endif /* HW_ATL2_LLH_H */
