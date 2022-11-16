/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 * Copyright (C) 2020 Marvell International Ltd.
 */

/* File hw_atl2_llh_internal.h: Preprocessor definitions
 * for Atlantic registers.
 */

#ifndef HW_ATL2_LLH_INTERNAL_H
#define HW_ATL2_LLH_INTERNAL_H

/* RX timestamp_req_desc{D} [1:0] Bitfield Definitions
 */
#define HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_ADR(descr) (0x00005B08 + (descr) * 0x20)
#define HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_MSK 0x00030000
#define HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_MSKN 0xFFFCFFFF
#define HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_SHIFT 16
#define HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_WIDTH 2
#define HW_ATL2_RPF_TIMESTAMP_REQ_DESCD_DEFAULT 0x0

/* RX pif_rpf_redir_2_en_i Bitfield Definitions
 * PORT="pif_rpf_redir_2_en_i"
 */
#define HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_ADR 0x000054C8
#define HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_MSK 0x00001000
#define HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_MSKN 0xFFFFEFFF
#define HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_SHIFT 12
#define HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_WIDTH 1
#define HW_ATL2_RPF_PIF_RPF_REDIR2_ENI_DEFAULT 0x0

/* RX pif_rpf_rss_hash_type_i Bitfield Definitions
 */
#define HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_ADR 0x000054C8
#define HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_MSK 0x000001FF
#define HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_MSKN 0xFFFFFE00
#define HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_SHIFT 0
#define HW_ATL2_RPF_PIF_RPF_RSS_HASH_TYPEI_WIDTH 9

/* rx rpf_new_rpf_en bitfield definitions
 * preprocessor definitions for the bitfield "rpf_new_rpf_en_i".
 * port="pif_rpf_new_rpf_en_i
 */

/* register address for bitfield rpf_new_rpf_en */
#define HW_ATL2_RPF_NEW_EN_ADR 0x00005104
/* bitmask for bitfield rpf_new_rpf_en */
#define HW_ATL2_RPF_NEW_EN_MSK 0x00000800
/* inverted bitmask for bitfield rpf_new_rpf_en */
#define HW_ATL2_RPF_NEW_EN_MSKN 0xfffff7ff
/* lower bit position of bitfield rpf_new_rpf_en */
#define HW_ATL2_RPF_NEW_EN_SHIFT 11
/* width of bitfield rpf_new_rpf_en */
#define HW_ATL2_RPF_NEW_EN_WIDTH 1
/* default value of bitfield rpf_new_rpf_en */
#define HW_ATL2_RPF_NEW_EN_DEFAULT 0x0

/* rx l2_uc_req_tag0{f}[5:0] bitfield definitions
 * preprocessor definitions for the bitfield "l2_uc_req_tag0{f}[7:0]".
 * parameter: filter {f} | stride size 0x8 | range [0, 37]
 * port="pif_rpf_l2_uc_req_tag0[5:0]"
 */

/* register address for bitfield l2_uc_req_tag0{f}[2:0] */
#define HW_ATL2_RPFL2UC_TAG_ADR(filter) (0x00005114 + (filter) * 0x8)
/* bitmask for bitfield l2_uc_req_tag0{f}[2:0] */
#define HW_ATL2_RPFL2UC_TAG_MSK 0x0FC00000
/* inverted bitmask for bitfield l2_uc_req_tag0{f}[2:0] */
#define HW_ATL2_RPFL2UC_TAG_MSKN 0xF03FFFFF
/* lower bit position of bitfield l2_uc_req_tag0{f}[2:0] */
#define HW_ATL2_RPFL2UC_TAG_SHIFT 22
/* width of bitfield l2_uc_req_tag0{f}[2:0] */
#define HW_ATL2_RPFL2UC_TAG_WIDTH 6
/* default value of bitfield l2_uc_req_tag0{f}[2:0] */
#define HW_ATL2_RPFL2UC_TAG_DEFAULT 0x0

/* rpf_l2_bc_req_tag[5:0] bitfield definitions
 * preprocessor definitions for the bitfield "rpf_l2_bc_req_tag[5:0]".
 * port="pifrpf_l2_bc_req_tag_i[5:0]"
 */

/* register address for bitfield rpf_l2_bc_req_tag */
#define HW_ATL2_RPF_L2_BC_TAG_ADR 0x000050F0
/* bitmask for bitfield rpf_l2_bc_req_tag */
#define HW_ATL2_RPF_L2_BC_TAG_MSK 0x0000003F
/* inverted bitmask for bitfield rpf_l2_bc_req_tag */
#define HW_ATL2_RPF_L2_BC_TAG_MSKN 0xffffffc0
/* lower bit position of bitfield rpf_l2_bc_req_tag */
#define HW_ATL2_RPF_L2_BC_TAG_SHIFT 0
/* width of bitfield rpf_l2_bc_req_tag */
#define HW_ATL2_RPF_L2_BC_TAG_WIDTH 6
/* default value of bitfield rpf_l2_bc_req_tag */
#define HW_ATL2_RPF_L2_BC_TAG_DEFAULT 0x0

/* rx rpf_rss_red1_data_[4:0] bitfield definitions
 * preprocessor definitions for the bitfield "rpf_rss_red1_data[4:0]".
 * port="pif_rpf_rss_red1_data_i[4:0]"
 */

/* register address for bitfield rpf_rss_red1_data[4:0] */
#define HW_ATL2_RPF_RSS_REDIR_ADR(TC, INDEX) (0x00006200 + \
					(0x100 * !!((TC) > 3)) + (INDEX) * 4)
/* bitmask for bitfield rpf_rss_red1_data[4:0] */
#define HW_ATL2_RPF_RSS_REDIR_MSK(TC)  (0x00000001F << (5 * ((TC) % 4)))
/* lower bit position of bitfield rpf_rss_red1_data[4:0] */
#define HW_ATL2_RPF_RSS_REDIR_SHIFT(TC) (5 * ((TC) % 4))
/* width of bitfield rpf_rss_red1_data[4:0] */
#define HW_ATL2_RPF_RSS_REDIR_WIDTH 5
/* default value of bitfield rpf_rss_red1_data[4:0] */
#define HW_ATL2_RPF_RSS_REDIR_DEFAULT 0x0

/* rx vlan_req_tag0{f}[3:0] bitfield definitions
 * preprocessor definitions for the bitfield "vlan_req_tag0{f}[3:0]".
 * parameter: filter {f} | stride size 0x4 | range [0, 15]
 * port="pif_rpf_vlan_req_tag0[3:0]"
 */

/* register address for bitfield vlan_req_tag0{f}[3:0] */
#define HW_ATL2_RPF_VL_TAG_ADR(filter) (0x00005290 + (filter) * 0x4)
/* bitmask for bitfield vlan_req_tag0{f}[3:0] */
#define HW_ATL2_RPF_VL_TAG_MSK 0x0000F000
/* inverted bitmask for bitfield vlan_req_tag0{f}[3:0] */
#define HW_ATL2_RPF_VL_TAG_MSKN 0xFFFF0FFF
/* lower bit position of bitfield vlan_req_tag0{f}[3:0] */
#define HW_ATL2_RPF_VL_TAG_SHIFT 12
/* width of bitfield vlan_req_tag0{f}[3:0] */
#define HW_ATL2_RPF_VL_TAG_WIDTH 4
/* default value of bitfield vlan_req_tag0{f}[3:0] */
#define HW_ATL2_RPF_VL_TAG_DEFAULT 0x0

/* rx etype_req_tag0{f}[2:0] bitfield definitions
 * preprocessor definitions for the bitfield "etype_req_tag0{f}[2:0]".
 * parameter: filter {f} | stride size 0x4 | range [0, 15]
 * port="pif_rpf_etype_req_tag0[2:0]"
 */

/* register address for bitfield etype_req_tag0{f}[2:0] */
#define HW_ATL2_RPF_ET_TAG_ADR(filter) (0x00005340 + (filter) * 0x4)
/* bitmask for bitfield etype_req_tag0{f}[2:0] */
#define HW_ATL2_RPF_ET_TAG_MSK 0x00000007
/* inverted bitmask for bitfield etype_req_tag0{f}[2:0] */
#define HW_ATL2_RPF_ET_TAG_MSKN 0xFFFFFFF8
/* lower bit position of bitfield etype_req_tag0{f}[2:0] */
#define HW_ATL2_RPF_ET_TAG_SHIFT 0
/* width of bitfield etype_req_tag0{f}[2:0] */
#define HW_ATL2_RPF_ET_TAG_WIDTH 3
/* default value of bitfield etype_req_tag0{f}[2:0] */
#define HW_ATL2_RPF_ET_TAG_DEFAULT 0x0

/* RX l3_l4_en{F} Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_l4_en{F}".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_l4_en_i[0]"
 */

/* Register address for bitfield l3_l4_en{F} */
#define HW_ATL2_RPF_L3_L4_ENF_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_l4_en{F} */
#define HW_ATL2_RPF_L3_L4_ENF_MSK 0x80000000u
/* Inverted bitmask for bitfield l3_l4_en{F} */
#define HW_ATL2_RPF_L3_L4_ENF_MSKN 0x7FFFFFFFu
/* Lower bit position of bitfield l3_l4_en{F} */
#define HW_ATL2_RPF_L3_L4_ENF_SHIFT 31
/* Width of bitfield l3_l4_en{F} */
#define HW_ATL2_RPF_L3_L4_ENF_WIDTH 1
/* Default value of bitfield l3_l4_en{F} */
#define HW_ATL2_RPF_L3_L4_ENF_DEFAULT 0x0

/* RX l3_v6_en{F} Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_v6_en{F}".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_v6_en_i[0]"
 */
/* Register address for bitfield l3_v6_en{F} */
#define HW_ATL2_RPF_L3_V6_ENF_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_v6_en{F} */
#define HW_ATL2_RPF_L3_V6_ENF_MSK 0x40000000u
/* Inverted bitmask for bitfield l3_v6_en{F} */
#define HW_ATL2_RPF_L3_V6_ENF_MSKN 0xBFFFFFFFu
/* Lower bit position of bitfield l3_v6_en{F} */
#define HW_ATL2_RPF_L3_V6_ENF_SHIFT 30
/* Width of bitfield l3_v6_en{F} */
#define HW_ATL2_RPF_L3_V6_ENF_WIDTH 1
/* Default value of bitfield l3_v6_en{F} */
#define HW_ATL2_RPF_L3_V6_ENF_DEFAULT 0x0

/* RX l3_sa{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_sa{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_sa_en_i[0]"
 */

/* Register address for bitfield l3_sa{F}_en */
#define HW_ATL2_RPF_L3_SAF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_sa{F}_en */
#define HW_ATL2_RPF_L3_SAF_EN_MSK 0x20000000u
/* Inverted bitmask for bitfield l3_sa{F}_en */
#define HW_ATL2_RPF_L3_SAF_EN_MSKN 0xDFFFFFFFu
/* Lower bit position of bitfield l3_sa{F}_en */
#define HW_ATL2_RPF_L3_SAF_EN_SHIFT 29
/* Width of bitfield l3_sa{F}_en */
#define HW_ATL2_RPF_L3_SAF_EN_WIDTH 1
/* Default value of bitfield l3_sa{F}_en */
#define HW_ATL2_RPF_L3_SAF_EN_DEFAULT 0x0

/* RX l3_da{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_da{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_da_en_i[0]"
 */

/* Register address for bitfield l3_da{F}_en */
#define HW_ATL2_RPF_L3_DAF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_da{F}_en */
#define HW_ATL2_RPF_L3_DAF_EN_MSK 0x10000000u
/* Inverted bitmask for bitfield l3_da{F}_en */
#define HW_ATL2_RPF_L3_DAF_EN_MSKN 0xEFFFFFFFu
/* Lower bit position of bitfield l3_da{F}_en */
#define HW_ATL2_RPF_L3_DAF_EN_SHIFT 28
/* Width of bitfield l3_da{F}_en */
#define HW_ATL2_RPF_L3_DAF_EN_WIDTH 1
/* Default value of bitfield l3_da{F}_en */
#define HW_ATL2_RPF_L3_DAF_EN_DEFAULT 0x0

/* RX l4_sp{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l4_sp{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l4_sp_en_i[0]"
 */

/* Register address for bitfield l4_sp{F}_en */
#define HW_ATL2_RPF_L4_SPF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l4_sp{F}_en */
#define HW_ATL2_RPF_L4_SPF_EN_MSK 0x08000000u
/* Inverted bitmask for bitfield l4_sp{F}_en */
#define HW_ATL2_RPF_L4_SPF_EN_MSKN 0xF7FFFFFFu
/* Lower bit position of bitfield l4_sp{F}_en */
#define HW_ATL2_RPF_L4_SPF_EN_SHIFT 27
/* Width of bitfield l4_sp{F}_en */
#define HW_ATL2_RPF_L4_SPF_EN_WIDTH 1
/* Default value of bitfield l4_sp{F}_en */
#define HW_ATL2_RPF_L4_SPF_EN_DEFAULT 0x0

/* RX l4_dp{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l4_dp{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l4_dp_en_i[0]"
 */

/* Register address for bitfield l4_dp{F}_en */
#define HW_ATL2_RPF_L4_DPF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l4_dp{F}_en */
#define HW_ATL2_RPF_L4_DPF_EN_MSK 0x04000000u
/* Inverted bitmask for bitfield l4_dp{F}_en */
#define HW_ATL2_RPF_L4_DPF_EN_MSKN 0xFBFFFFFFu
/* Lower bit position of bitfield l4_dp{F}_en */
#define HW_ATL2_RPF_L4_DPF_EN_SHIFT 26
/* Width of bitfield l4_dp{F}_en */
#define HW_ATL2_RPF_L4_DPF_EN_WIDTH 1
/* Default value of bitfield l4_dp{F}_en */
#define HW_ATL2_RPF_L4_DPF_EN_DEFAULT 0x0

/* RX l4_prot{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l4_prot{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l4_prot_en_i[0]"
 */

/* Register address for bitfield l4_prot{F}_en */
#define HW_ATL2_RPF_L4_PROTF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l4_prot{F}_en */
#define HW_ATL2_RPF_L4_PROTF_EN_MSK 0x02000000u
/* Inverted bitmask for bitfield l4_prot{F}_en */
#define HW_ATL2_RPF_L4_PROTF_EN_MSKN 0xFDFFFFFFu
/* Lower bit position of bitfield l4_prot{F}_en */
#define HW_ATL2_RPF_L4_PROTF_EN_SHIFT 25
/* Width of bitfield l4_prot{F}_en */
#define HW_ATL2_RPF_L4_PROTF_EN_WIDTH 1
/* Default value of bitfield l4_prot{F}_en */
#define HW_ATL2_RPF_L4_PROTF_EN_DEFAULT 0x0

/* RX l3_arp{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_arp{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_arp_en_i[0]"
 */

/* Register address for bitfield l3_arp{F}_en */
#define HW_ATL2_RPF_L3_ARPF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_arp{F}_en */
#define HW_ATL2_RPF_L3_ARPF_EN_MSK 0x01000000u
/* Inverted bitmask for bitfield l3_arp{F}_en */
#define HW_ATL2_RPF_L3_ARPF_EN_MSKN 0xFEFFFFFFu
/* Lower bit position of bitfield l3_arp{F}_en */
#define HW_ATL2_RPF_L3_ARPF_EN_SHIFT 24
/* Width of bitfield l3_arp{F}_en */
#define HW_ATL2_RPF_L3_ARPF_EN_WIDTH 1
/* Default value of bitfield l3_arp{F}_en */
#define HW_ATL2_RPF_L3_ARPF_EN_DEFAULT 0x0

/* RX l3_l4_rxq{F}_en Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_l4_rxq{F}_en".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_l4_rxq_en_i[0]"
 */

/* Register address for bitfield l3_l4_RXq{F}_en */
#define HW_ATL2_RPF_L3_L4_RXQF_EN_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_l4_RXq{F}_en */
#define HW_ATL2_RPF_L3_L4_RXQF_EN_MSK 0x00800000u
/* Inverted bitmask for bitfield l3_l4_RXq{F}_en */
#define HW_ATL2_RPF_L3_L4_RXQF_EN_MSKN 0xFF7FFFFFu
/* Lower bit position of bitfield l3_l4_RXq{F}_en */
#define HW_ATL2_RPF_L3_L4_RXQF_EN_SHIFT 23
/* Width of bitfield l3_l4_RXq{F}_en */
#define HW_ATL2_RPF_L3_L4_RXQF_EN_WIDTH 1
/* Default value of bitfield l3_l4_RXq{F}_en */
#define HW_ATL2_RPF_L3_L4_RXQF_EN_DEFAULT 0x0

/* RX l3_l4_mng_RXq{F} Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_l4_mng_RXq{F}".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_l4_mng_rxq_i[0]"
 */

/* Register address for bitfield l3_l4_mng_rxq{F} */
#define HW_ATL2_RPF_L3_L4_MNG_RXQF_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_l4_mng_rxq{F} */
#define HW_ATL2_RPF_L3_L4_MNG_RXQF_MSK 0x00400000u
/* Inverted bitmask for bitfield l3_l4_mng_rxq{F} */
#define HW_ATL2_RPF_L3_L4_MNG_RXQF_MSKN 0xFFBFFFFFu
/* Lower bit position of bitfield l3_l4_mng_rxq{F} */
#define HW_ATL2_RPF_L3_L4_MNG_RXQF_SHIFT 22
/* Width of bitfield l3_l4_mng_rxq{F} */
#define HW_ATL2_RPF_L3_L4_MNG_RXQF_WIDTH 1
/* Default value of bitfield l3_l4_mng_rxq{F} */
#define HW_ATL2_RPF_L3_L4_MNG_RXQF_DEFAULT 0x0

/* RX l3_l4_act{F}[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_l4_act{F}[2:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_l4_act0_i[2:0]"
 */

/* Register address for bitfield l3_l4_act{F}[2:0] */
#define HW_ATL2_RPF_L3_L4_ACTF_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_l4_act{F}[2:0] */
#define HW_ATL2_RPF_L3_L4_ACTF_MSK 0x00070000u
/* Inverted bitmask for bitfield l3_l4_act{F}[2:0] */
#define HW_ATL2_RPF_L3_L4_ACTF_MSKN 0xFFF8FFFFu
/* Lower bit position of bitfield l3_l4_act{F}[2:0] */
#define HW_ATL2_RPF_L3_L4_ACTF_SHIFT 16
/* Width of bitfield l3_l4_act{F}[2:0] */
#define HW_ATL2_RPF_L3_L4_ACTF_WIDTH 3
/* Default value of bitfield l3_l4_act{F}[2:0] */
#define HW_ATL2_RPF_L3_L4_ACTF_DEFAULT 0x0

/* RX l3_l4_rxq{F}[4:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "l3_l4_rxq{F}[4:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_l4_rxq0_i[4:0]"
 */

/* Register address for bitfield l3_l4_rxq{F}[4:0] */
#define HW_ATL2_RPF_L3_L4_RXQF_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l3_l4_rxq{F}[4:0] */
#define HW_ATL2_RPF_L3_L4_RXQF_MSK 0x00001F00u
/* Inverted bitmask for bitfield l3_l4_rxq{F}[4:0] */
#define HW_ATL2_RPF_L3_L4_RXQF_MSKN 0xFFFFE0FFu
/* Lower bit position of bitfield l3_l4_rxq{F}[4:0] */
#define HW_ATL2_RPF_L3_L4_RXQF_SHIFT 8
/* Width of bitfield l3_l4_rxq{F}[4:0] */
#define HW_ATL2_RPF_L3_L4_RXQF_WIDTH 5
/* Default value of bitfield l3_l4_rxq{F}[4:0] */
#define HW_ATL2_RPF_L3_L4_RXQF_DEFAULT 0x0

/* RX rpf_l3_v6_sa{F}_dw{D}[1F:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_v6_sa{F}_dw{D}[1F:0]".
 * Parameter: filter {F} | stride size 0x10 | range [0, 7]
 * Parameter: dword {D} | stride size 0x4 | range [0, 3]
 * PORT="pif_rpf_l3_v6_sa{F}_dw0[1F:0]"
 */

/* Register address for bitfield rpf_l3_v6_sa{F}_dw{D}[1F:0] */
#define HW_ATL2_RPF_L3_SA_DW_ADR(filter, dword) \
	(0x00006400u + (filter) * 0x10 + (dword) * 0x4)

/* RX rpf_l3_v6_da{F}_dw{D}[1F:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_v6_da{F}_dw{D}[1F:0]".
 * Parameter: filter {F} | stride size 0x10 | range [0, 7]
 * Parameter: dword {D} | stride size 0x4 | range [0, 3]
 * PORT="pif_rpf_l3_v6_da{F}_dw{D}[1F:0]"
 */

/* Register address for bitfield rpf_l3_v6_da{F}_dw{D}[1F:0] */
#define HW_ATL2_RPF_L3_DA_DW_ADR(filter, dword) \
	(0x00006480u + (filter) * 0x10 + (dword) * 0x4)

/* RX rpf_l3_cmd{F}[1F:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_cmd{F}[1F:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_v4_cmd{F}[1F:0]"
 */

/* Register address for bitfield rpf_l3_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V4_CMD_ADR(filter) (0x00006500u + (filter) * 0x4)
/* Bitmask for bitfield rpf_l3_cmd{F}[F:0] */
#define HW_ATL2_RPF_L3_V4_CMD_MSK 0x0000FFFFu
/* Lower bit position of bitfield rpf_l3_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V4_CMD_SHIFT 0
/* Width of bitfield rpf_l3_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V4_CMD_WIDTH 16
/* Default value of bitfield rpf_l3_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V4_CMD_DEFAULT 0x0


/* RX rpf_l3_v6_cmd{F}[1F:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_v6_cmd{F}[1F:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_v6_cmd{F}[1F:0]"
 */

/* Register address for bitfield rpf_l3_v6_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V6_CMD_ADR(filter) (0x00006500u + (filter) * 0x4)
/* Bitmask for bitfield rpf_l3_v6_cmd{F}[F:0] */
#define HW_ATL2_RPF_L3_V6_CMD_MSK 0xFF7F0000u
/* Lower bit position of bitfield rpf_l3_v6_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V6_CMD_SHIFT 0
/* Width of bitfield rpf_l3_v6_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V6_CMD_WIDTH 32
/* Default value of bitfield rpf_l3_v6_cmd{F}[1F:0] */
#define HW_ATL2_RPF_L3_V6_CMD_DEFAULT 0x0

/* RX rpf_l3_v6_v4_select Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_v6_v4_select".
 * PORT="pif_rpf_l3_v6_v4_select"
 */

/* Register address for bitfield rpf_l3_v6_cmd{F}[F:0] */
#define HW_ATL2_RPF_L3_V6_V4_SELECT_ADR 0x00006500u
/* Bitmask for bitfield pif_rpf_l3_v6_v4_select*/
#define HW_ATL2_RPF_L3_V6_V4_SELECT_MSK 0x00800000u
/* Inverted bitmask for bitfield pif_rpf_l3_v6_v4_select */
#define HW_ATL2_RPF_L3_V6_V4_SELECT_MSKN 0xFF7FFFFFu
/* Lower bit position of bitfield pif_rpf_l3_v6_v4_select */
#define HW_ATL2_RPF_L3_V6_V4_SELECT_SHIFT 23
/* Width of bitfield pif_rpf_l3_v6_v4_select */
#define HW_ATL2_RPF_L3_V6_V4_SELECT_WIDTH 1
/* Default value of bitfield pif_rpf_l3_v6_v4_select*/
#define HW_ATL2_RPF_L3_V6_V4_SELECT_DEFAULT 0x0

/* RX rpf_l3_v4_req_tag{F}[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_v4_req_tag{F}[2:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_v4_req_tag0[2:0]"
 */

/* Register address for bitfield rpf_l3_v4_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V4_TAG_ADR(filter) (0x00006500u + (filter) * 0x4)
/* Bitmask for bitfield rpf_l3_v4_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V4_TAG_MSK 0x00000070u
/* Inverted bitmask for bitfield rpf_l3_v4_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V4_TAG_MSKN 0xFFFFFF8Fu
/* Lower bit position of bitfield rpf_l3_v4_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V4_TAG_SHIFT 4
/* Width of bitfield rpf_l3_v4_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V4_TAG_WIDTH 3
/* Default value of bitfield rpf_l3_v4_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V4_TAG_DEFAULT 0x0

/* RX rpf_l3_v6_req_tag{F}[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l3_v6_req_tag{F}[2:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l3_v6_req_tag0[2:0]"
 */

/* Register address for bitfield rpf_l3_v6_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V6_TAG_ADR(filter) (0x00006500u + (filter) * 0x4)
/* Bitmask for bitfield rpf_l3_v6_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V6_TAG_MSK 0x00700000
/* Inverted bitmask for bitfield rpf_l3_v6_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V6_TAG_MSKN 0xFF8FFFFFu
/* Lower bit position of bitfield rpf_l3_v6_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V6_TAG_SHIFT 20
/* Width of bitfield rpf_l3_v6_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V6_TAG_WIDTH 3
/* Default value of bitfield rpf_l3_v6_req_tag{F}[2:0] */
#define HW_ATL2_RPF_L3_V6_TAG_DEFAULT 0x0

/* RX rpf_l4_cmd{F}[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l4_cmd{F}[2:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l4_cmd{F}[2:0]"
 */

/* Register address for bitfield rpf_l4_cmd{F}[2:0] */
#define HW_ATL2_RPF_L4_CMD_ADR(filter) (0x00006520u + (filter) * 0x4)
/* Bitmask for bitfield rpf_l4_cmd{F}[2:0] */
#define HW_ATL2_RPF_L4_CMD_MSK 0x00000007u
/* Inverted bitmask for bitfield rpf_l4_cmd{F}[2:0] */
#define HW_ATL2_RPF_L4_CMD_MSKN 0xFFFFFFF8u
/* Lower bit position of bitfield rpf_l4_cmd{F}[2:0] */
#define HW_ATL2_RPF_L4_CMD_SHIFT 0
/* Width of bitfield rpf_l4_cmd{F}[2:0]*/
#define HW_ATL2_RPF_L4_CMD_WIDTH 3
/* Default value of bitfield rpf_l4_cmd{F}[2:0] */
#define HW_ATL2_RPF_L4_CMD_DEFAULT 0x0

/* RX rpf_l4_req_tag{F}[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_l4_tag{F}[2:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l4_tag{F}[2:0]"
 */

/* Register address for bitfield rpf_l4_tag{F}[2:0] */
#define HW_ATL2_RPF_L4_TAG_ADR(filter) (0x00006520u + (filter) * 0x4)
/* Bitmask for bitfield rpf_l4_tag{F}[2:0] */
#define HW_ATL2_RPF_L4_TAG_MSK 0x00000070u
/* Inverted bitmask for bitfield rpf_l4_tag{F}[2:0] */
#define HW_ATL2_RPF_L4_TAG_MSKN 0xFFFFFF8Fu
/* Lower bit position of bitfield rpf_l4_tag{F}[2:0] */
#define HW_ATL2_RPF_L4_TAG_SHIFT 4
/* Width of bitfield rpf_l4_tag{F}[2:0]*/
#define HW_ATL2_RPF_L4_TAG_WIDTH 3
/* Default value of bitfield rpf_l4_tag{F}[2:0] */
#define HW_ATL2_RPF_L4_TAG_DEFAULT 0x0

/* RX l4_prot{F}[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "l4_prot{F}[2:0]".
 * Parameter: filter {F} | stride size 0x4 | range [0, 7]
 * PORT="pif_rpf_l4_prot0_i[2:0]"
 */

/* Register address for bitfield l4_prot{F}[2:0] */
#define HW_ATL2_RPF_L4_PROTF_ADR(filter) (0x00005380u + (filter) * 0x4)
/* Bitmask for bitfield l4_prot{F}[2:0] */
#define HW_ATL2_RPF_L4_PROTF_MSK 0x00000007u
/* Inverted bitmask for bitfield l4_prot{F}[2:0] */
#define HW_ATL2_RPF_L4_PROTF_MSKN 0xFFFFFFF8u
/* Lower bit position of bitfield l4_prot{F}[2:0] */
#define HW_ATL2_RPF_L4_PROTF_SHIFT 0
/* Width of bitfield l4_prot{F}[2:0] */
#define HW_ATL2_RPF_L4_PROTF_WIDTH 3
/* Default value of bitfield l4_prot{F}[2:0] */
#define HW_ATL2_RPF_L4_PROTF_DEFAULT 0x0

/* RX rx_q{Q}_tc_map[2:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rx_q{Q}_tc_map[2:0]".
 * Parameter: Queue {Q} | bit-level stride | range [0, 31]
 * PORT="pif_rx_q0_tc_map_i[2:0]"
 */

/* Register address for bitfield rx_q{Q}_tc_map[2:0] */
#define HW_ATL2_RX_Q_TC_MAP_ADR(queue) \
	(((queue) < 32) ? 0x00005900 + ((queue) / 8) * 4 : 0)
/* Lower bit position of bitfield rx_q{Q}_tc_map[2:0] */
#define HW_ATL2_RX_Q_TC_MAP_SHIFT(queue) \
	(((queue) < 32) ? ((queue) * 4) % 32 : 0)
/* Width of bitfield rx_q{Q}_tc_map[2:0] */
#define HW_ATL2_RX_Q_TC_MAP_WIDTH 3
/* Default value of bitfield rx_q{Q}_tc_map[2:0] */
#define HW_ATL2_RX_Q_TC_MAP_DEFAULT 0x0

#define HW_ATL2_RDM_RX_DESC_RD_REQ_LIMIT_ADR 0x00005A04

/* TX desc{D}_ts_wrb_en Bitfield Definitions
 */
#define HW_ATL2_TDM_DESCD_TS_WRB_EN_ADR(descriptor) \
	(0x00007C08 + (descriptor) * 0x40)
#define HW_ATL2_TDM_DESCD_TS_WRB_EN_MSK 0x00040000
#define HW_ATL2_TDM_DESCD_TS_WRB_EN_MSKN 0xFFFBFFFF
#define HW_ATL2_TDM_DESCD_TS_WRB_EN_SHIFT 18
#define HW_ATL2_TDM_DESCD_TS_WRB_EN_WIDTH 1
#define HW_ATL2_TDM_DESCD_TS_WRB_EN_DEFAULT 0x0

/* TX desc{D}_ts_en Bitfield Definitions
 */
#define HW_ATL2_TDM_DESCD_TS_EN_ADR(descriptor) \
	(0x00007C08 + (descriptor) * 0x40)
#define HW_ATL2_TDM_DESCD_TS_EN_MSK 0x00020000
#define HW_ATL2_TDM_DESCD_TS_EN_MSKN 0xFFFDFFFF
#define HW_ATL2_TDM_DESCD_TS_EN_SHIFT 17
#define HW_ATL2_TDM_DESCD_TS_EN_WIDTH 1
#define HW_ATL2_TDM_DESCD_TS_EN_DEFAULT 0x0

/* TX desc{D}_avb_en Bitfield Definitions
 */
#define HW_ATL2_TDM_DESCD_AVB_EN_ADR(descriptor) \
	(0x00007C08 + (descriptor) * 0x40)
#define HW_ATL2_TDM_DESCD_AVB_EN_MSK 0x00010000
#define HW_ATL2_TDM_DESCD_AVB_EN_MSKN 0xFFFEFFFF
#define HW_ATL2_TDM_DESCD_AVB_EN_SHIFT 16
#define HW_ATL2_TDM_DESCD_AVB_EN_WIDTH 1
#define HW_ATL2_TDM_DESCD_AVB_EN_DEFAULT 0x0

/* tx tx_tc_q_rand_map_en bitfield definitions
 * preprocessor definitions for the bitfield "tx_tc_q_rand_map_en".
 * port="pif_tpb_tx_tc_q_rand_map_en_i"
 */

/* register address for bitfield tx_tc_q_rand_map_en */
#define HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_ADR 0x00007900
/* bitmask for bitfield tx_tc_q_rand_map_en */
#define HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_MSK 0x00000200
/* inverted bitmask for bitfield tx_tc_q_rand_map_en */
#define HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_MSKN 0xFFFFFDFF
/* lower bit position of bitfield tx_tc_q_rand_map_en */
#define HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_SHIFT 9
/* width of bitfield tx_tc_q_rand_map_en */
#define HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_WIDTH 1
/* default value of bitfield tx_tc_q_rand_map_en */
#define HW_ATL2_TPB_TX_TC_Q_RAND_MAP_EN_DEFAULT 0x0

/* tx tx_buffer_clk_gate_en bitfield definitions
 * preprocessor definitions for the bitfield "tx_buffer_clk_gate_en".
 * port="pif_tpb_tx_buffer_clk_gate_en_i"
 */

/* register address for bitfield tx_buffer_clk_gate_en */
#define HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_ADR 0x00007900
/* bitmask for bitfield tx_buffer_clk_gate_en */
#define HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_MSK 0x00000020
/* inverted bitmask for bitfield tx_buffer_clk_gate_en */
#define HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_MSKN 0xffffffdf
/* lower bit position of bitfield tx_buffer_clk_gate_en */
#define HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_SHIFT 5
/* width of bitfield tx_buffer_clk_gate_en */
#define HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_WIDTH 1
/* default value of bitfield tx_buffer_clk_gate_en */
#define HW_ATL2_TPB_TX_BUF_CLK_GATE_EN_DEFAULT 0x0

/* tx tx_q_tc_map{q} bitfield definitions
 * preprocessor definitions for the bitfield "tx_q_tc_map{q}".
 * parameter: queue {q} | bit-level stride | range [0, 31]
 * port="pif_tpb_tx_q_tc_map0_i[2:0]"
 */

/* register address for bitfield tx_q_tc_map{q} */
#define HW_ATL2_TX_Q_TC_MAP_ADR(queue) \
	(((queue) < 32) ? 0x0000799C + ((queue) / 4) * 4 : 0)
/* lower bit position of bitfield tx_q_tc_map{q} */
#define HW_ATL2_TX_Q_TC_MAP_SHIFT(queue) \
	(((queue) < 32) ? ((queue) * 8) % 32 : 0)
/* width of bitfield tx_q_tc_map{q} */
#define HW_ATL2_TX_Q_TC_MAP_WIDTH 3
/* default value of bitfield tx_q_tc_map{q} */
#define HW_ATL2_TX_Q_TC_MAP_DEFAULT 0x0

/* tx data_tc_arb_mode bitfield definitions
 * preprocessor definitions for the bitfield "data_tc_arb_mode".
 * port="pif_tps_data_tc_arb_mode_i"
 */

/* register address for bitfield data_tc_arb_mode */
#define HW_ATL2_TPS_DATA_TC_ARB_MODE_ADR 0x00007100
/* bitmask for bitfield data_tc_arb_mode */
#define HW_ATL2_TPS_DATA_TC_ARB_MODE_MSK 0x00000003
/* inverted bitmask for bitfield data_tc_arb_mode */
#define HW_ATL2_TPS_DATA_TC_ARB_MODE_MSKN 0xfffffffc
/* lower bit position of bitfield data_tc_arb_mode */
#define HW_ATL2_TPS_DATA_TC_ARB_MODE_SHIFT 0
/* width of bitfield data_tc_arb_mode */
#define HW_ATL2_TPS_DATA_TC_ARB_MODE_WIDTH 2
/* default value of bitfield data_tc_arb_mode */
#define HW_ATL2_TPS_DATA_TC_ARB_MODE_DEFAULT 0x0

/* tx data_tc{t}_credit_max[f:0] bitfield definitions
 * preprocessor definitions for the bitfield "data_tc{t}_credit_max[f:0]".
 * parameter: tc {t} | stride size 0x4 | range [0, 7]
 * port="pif_tps_data_tc0_credit_max_i[15:0]"
 */

/* register address for bitfield data_tc{t}_credit_max[f:0] */
#define HW_ATL2_TPS_DATA_TCTCREDIT_MAX_ADR(tc) (0x00007110 + (tc) * 0x4)
/* bitmask for bitfield data_tc{t}_credit_max[f:0] */
#define HW_ATL2_TPS_DATA_TCTCREDIT_MAX_MSK 0xffff0000
/* inverted bitmask for bitfield data_tc{t}_credit_max[f:0] */
#define HW_ATL2_TPS_DATA_TCTCREDIT_MAX_MSKN 0x0000ffff
/* lower bit position of bitfield data_tc{t}_credit_max[f:0] */
#define HW_ATL2_TPS_DATA_TCTCREDIT_MAX_SHIFT 16
/* width of bitfield data_tc{t}_credit_max[f:0] */
#define HW_ATL2_TPS_DATA_TCTCREDIT_MAX_WIDTH 16
/* default value of bitfield data_tc{t}_credit_max[f:0] */
#define HW_ATL2_TPS_DATA_TCTCREDIT_MAX_DEFAULT 0x0

/* tx pif_tpb_highest_prio_tc_en bitfield definitions
 * preprocessor definitions for the bitfield "pif_tpb_highest_prio_tc_en".
 * type: R/W
 * notes: Enable highest priority TC
 * If set, the configured highest priority TC will be scheduled
 * with highest priority.
 * port="pif_tpb_highest_prio_tc_en_i"
 */

/* register address for bitfield pif_tpb_highest_prio_tc_en */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_ADR 0x00007180
/* bitmask for bitfield pif_tpb_highest_prio_tc_en */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_MSK 0x00000100
/* inverted bitmask for bitfield pif_tpb_highest_prio_tc_en */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_MSKN 0xFFFFFEFF
/* lower bit position of bitfield pif_tpb_highest_prio_tc_en */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_SHIFT 8
/* width of bitfield pif_tpb_highest_prio_tc_en */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_WIDTH 1
/* default value of bitfield pif_tpb_highest_prio_tc_en */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_EN_DEFAULT 0x0

/* tx pif_tpb_highest_prio_tc bitfield definitions
 * preprocessor definitions for the bitfield "pif_tpb_highest_prio_tc".
 * type: R/W
 * notes: Configure a single TC in TPB that has highest priority.
 * If enabled, this TC will be scheduled with higher priority than
 * any AVB or mng-inj traffic.
 * port="pif_tpb_highest_prio_tc_i[2:0]"
 */

/* register address for bitfield pif_tpb_highest_prio_tc */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_ADR 0x00007180
/* bitmask for bitfield pif_tpb_highest_prio_tc */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_MSK 0x00000007
/* inverted bitmask for bitfield pif_tpb_highest_prio_tc */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_MSKN 0xFFFFFFF8
/* lower bit position of bitfield pif_tpb_highest_prio_tc */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_SHIFT 0
/* width of bitfield pif_tpb_highest_prio_tc */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_WIDTH 3
/* default value of bitfield pif_tpb_highest_prio_tc */
#define HW_ATL2_TPB_HIGHEST_PRIO_TC_DEFAULT 0x0

/* tx data_tc{t}_weight[e:0] bitfield definitions
 * preprocessor definitions for the bitfield "data_tc{t}_weight[e:0]".
 * parameter: tc {t} | stride size 0x4 | range [0, 7]
 * port="pif_tps_data_tc0_weight_i[14:0]"
 */

/* register address for bitfield data_tc{t}_weight[e:0] */
#define HW_ATL2_TPS_DATA_TCTWEIGHT_ADR(tc) (0x00007110 + (tc) * 0x4)
/* bitmask for bitfield data_tc{t}_weight[e:0] */
#define HW_ATL2_TPS_DATA_TCTWEIGHT_MSK 0x00007fff
/* inverted bitmask for bitfield data_tc{t}_weight[e:0] */
#define HW_ATL2_TPS_DATA_TCTWEIGHT_MSKN 0xffff8000
/* lower bit position of bitfield data_tc{t}_weight[e:0] */
#define HW_ATL2_TPS_DATA_TCTWEIGHT_SHIFT 0
/* width of bitfield data_tc{t}_weight[e:0] */
#define HW_ATL2_TPS_DATA_TCTWEIGHT_WIDTH 15
/* default value of bitfield data_tc{t}_weight[e:0] */
#define HW_ATL2_TPS_DATA_TCTWEIGHT_DEFAULT 0x0

/* TX TDM AVB Prefetch Delay Value Register 0 Definitions
 */
#define HW_ATL2_TX_TDM_AVB_PREFETCH_DELAY_VALUE0_ADR(queue) \
	(0x00007C24u + (queue) * 0x40)

/* tx interrupt moderation control register definitions
 * Preprocessor definitions for TX Interrupt Moderation Control Register
 * Base Address: 0x00007c28
 * Parameter: queue {Q} | stride size 0x4 | range [0, 31]
 */

#define HW_ATL2_TX_INTR_MODERATION_CTL_ADR(queue) (0x00007c28u + (queue) * 0x40)

/* TX tx_data_rd_req_limit[7:0] Bitfield Definitions
 */
#define HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_ADR 0x00007B04
#define HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_MSK 0x0000FF00
#define HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_MSKN 0xFFFF00FF
#define HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_SHIFT 8
#define HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_WIDTH 8
#define HW_ATL2_TDM_TX_DATA_RD_REQ_LIMIT_DEFAULT 0x10

/* TX tx_desc_rd_req_limit[4:0] Bitfield Definitions
 */
#define HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_ADR 0x00007B04
#define HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_MSK 0x0000001F
#define HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_MSKN 0xFFFFFFE0
#define HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_SHIFT 0
#define HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_WIDTH 5
#define HW_ATL2_TDM_TX_DESC_RD_REQ_LIMIT_DEFAULT 0x8

/* global microprocessor scratch pad definitions */
#define HW_ATL2_GLB_CPU_SCRATCH_SCP_ADR(scratch_scp) \
	(0x00000300u + (scratch_scp) * 0x4)

/* register address for bitfield uP Force Interrupt */
#define HW_ATL2_GLB_CONTROL_2_ADR 0x00000404

/* bitmask for bitfield MIF Interrupt to ITR */
#define HW_ATL2_MIF_INTERRUPT_TO_ITR_MSK 0x000003c0
#define HW_ATL2_MIF_INTERRUPT_0_TO_ITR_MSK 0x00000040
#define HW_ATL2_MIF_INTERRUPT_1_TO_ITR_MSK 0x00000080
#define HW_ATL2_MIF_INTERRUPT_2_TO_ITR_MSK 0x00000100
#define HW_ATL2_MIF_INTERRUPT_3_TO_ITR_MSK 0x00000200

/* lower bit position of bitfield MIF Interrupt to ITR */
#define HW_ATL2_MIF_INTERRUPT_TO_ITR_SHIFT 6

/* width of bitfield MIF Interrupt to ITR */
#define HW_ATL2_MIF_INTERRUPT_TO_ITR_WIDTH 4

/* default value of bitfield MIF Interrupt to ITR */
#define HW_ATL2_MIF_INTERRUPT_TO_ITR_DEFAULT 0x3

/* bitmask for bitfield Enable MIF Interrupt to ITR */
#define HW_ATL2_EN_INTERRUPT_TO_ITR_MSK 0x00003c00
#define HW_ATL2_EN_INTERRUPT_MIF0_TO_ITR_MSK 0x00000400
#define HW_ATL2_EN_INTERRUPT_MIF1_TO_ITR_MSK 0x00000800
#define HW_ATL2_EN_INTERRUPT_MIF2_TO_ITR_MSK 0x00001000
#define HW_ATL2_EN_INTERRUPT_MIF3_TO_ITR_MSK 0x00002000

/* lower bit position of bitfield Enable MIF Interrupt to ITR */
#define HW_ATL2_EN_INTERRUPT_TO_ITR_SHIFT 0xA

/* width of bitfield Enable MIF Interrupt to ITR */
#define HW_ATL2_EN_INTERRUPT_TO_ITR_WIDTH 4

/* default value of bitfield Enable MIF Interrupt to ITR */
#define HW_ATL2_EN_INTERRUPT_TO_ITR_DEFAULT 0x0

/* preprocessor definitions for the bitfield
 * "Primary Timestamp Clock Source Selection".
 */

/* register address for bitfield */
#define  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_ADR 0x00004500
/* bitmask for bitfield  */
#define  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_MSK 0x00000080
/* inverted bitmask for bitfield  */
#define  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_MSKN 0xFFFFFF7F
/* lower bit position of bitfield  */
#define  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_SHIFT 7
/* width of bitfield  */
#define  HW_ATL2_PRIMARY_TS_CLK_SRC_SLCT_WIDTH 1


/* register address for bitfield uP High Priority Interrupt */
#define HW_ATL2_GLOBAL_ALARMS_1_ADR 0x00000904
#define HW_ATL2_GLOBAL_INTERNAL_ALARMS_1_ADR 0x00000924
#define HW_ATL2_GLOBAL_LASI_1_MASK_ADR 0x00000944
#define HW_ATL2_GLOBAL_HIGH_PRIO_INTERRUPT_1_MASK_ADR 0x00000964
#define HW_ATL2_GLOBAL_LOW_PRIO_INTERRUPT_1_MASK_ADR 0x00000984
/* bitmask for bitfield TSG PTM GPIO interrupt */
#define HW_ATL2_TSG_TSG1_GPIO_INTERRUPT_MSK 0x00000200
/* lower bit position of bitfield TSG PTM GPIO interrupt */
#define HW_ATL2_TSG_TSG1_GPIO_INTERRUPT_SHIFT 9
/* bitmask for bitfield TSG0 GPIO interrupt */
#define HW_ATL2_TSG_TSG0_GPIO_INTERRUPT_MSK 0x00000020
/* lower bit position of bitfield TSG0 GPIO interrupt */
#define HW_ATL2_TSG_TSG0_GPIO_INTERRUPT_SHIFT 5

/* TSG registers */
#define HW_ATL2_TSG_REG_ADR(clk, reg_name) \
	(clk == 0 ? HW_ATL2_CLK0_##reg_name##_ADR :\
		 HW_ATL2_CLK1_##reg_name##_ADR)

#define HW_ATL2_CLK0_CLOCK_CFG_ADR 0x00000CA0u
#define HW_ATL2_CLK1_CLOCK_CFG_ADR 0x00000D50u
#define HW_ATL2_TSG_SYNC_RESET_MSK 0x00000001
#define HW_ATL2_TSG_SYNC_RESET_SHIFT 0x00000000
#define HW_ATL2_TSG_CLOCK_EN_MSK 0x00000002
#define HW_ATL2_TSG_CLOCK_EN_SHIFT 0x00000001
#define HW_ATL2_TSG_CLOCK_MUX_SELECT_MSK 0x0000000C
#define HW_ATL2_TSG_CLOCK_MUX_SELECT_SHIFT 0x00000002
#define HW_ATL2_TSG_CLOCK_MUX_INTERNAL 0x00000000
#define HW_ATL2_TSG_CLOCK_MUX_REFERENCE 0x00000001
#define HW_ATL2_TSG_CLOCK_MUX_GPIO 0x00000002
#define HW_ATL2_TSG_CLOCK_MUX_1588 0x00000003

#define HW_ATL2_CLK0_CLOCK_MODIF_CTRL_ADR 0x00000CA4u
#define HW_ATL2_CLK1_CLOCK_MODIF_CTRL_ADR 0x00000D54u
#define HW_ATL2_TSG_SET_COUNTER_MSK 0x00000001
#define HW_ATL2_TSG_SUBTRACT_COUNTER_MSK 0x00000002
#define HW_ATL2_TSG_ADD_COUNTER_MSK 0x00000004
#define HW_ATL2_TSG_LOAD_INC_CFG_MSK 0x00000008
#define HW_ATL2_TSG_SET_PERIODIC_CORRECTION_MSK 0x00000010

#define HW_ATL2_CLK0_CLOCK_MODIF_VAL_LSW_ADR 0x00000CA8u
#define HW_ATL2_CLK1_CLOCK_MODIF_VAL_LSW_ADR 0x00000D58u

#define HW_ATL2_CLK0_CLOCK_MODIF_VAL_MSW_ADR 0x00000Cacu
#define HW_ATL2_CLK1_CLOCK_MODIF_VAL_MSW_ADR 0x00000D5cu

#define HW_ATL2_CLK0_CLOCK_INC_CFG_ADR 0x00000CB0u
#define HW_ATL2_CLK1_CLOCK_INC_CFG_ADR 0x00000D60u
#define HW_ATL2_TSG_CLOCK_INC_CFG_NS_SHIFT 0x00000000
#define HW_ATL2_TSG_CLOCK_INC_CFG_NS_MSK 0x000000FF
#define HW_ATL2_TSG_CLOCK_INC_CFG_FNS_SHIFT 0x00000018
#define HW_ATL2_TSG_CLOCK_INC_CFG_FNS_MSK 0xFFFFFF00

#define HW_ATL2_CLK0_PERIODIC_CORRECTION_ADR 0x00000CB4u
#define HW_ATL2_CLK1_PERIODIC_CORRECTION_ADR 0x00000D64u
#define HW_ATL2_TSG_PERIODIC_CORRECTION_PERIOD_SHIFT 0x00000000
#define HW_ATL2_TSG_PERIODIC_CORRECTION_PERIOD_MSK 0x000000FF
#define HW_ATL2_TSG_CLOCK_PERIODIC_CORRECTION_FNS_SHIFT 0x00000018
#define HW_ATL2_TSG_CLOCK_PERIODIC_CORRECTION_FNS_MSK 0xFFFFFF00

#define HW_ATL2_CLK0_READ_CUR_NS_LSW_ADR 0x00000CB8u
#define HW_ATL2_CLK1_READ_CUR_NS_LSW_ADR 0x00000D68u

#define HW_ATL2_CLK0_READ_CUR_NS_MSW_ADR 0x00000CBCu
#define HW_ATL2_CLK1_READ_CUR_NS_MSW_ADR 0x00000D6cu

#define HW_ATL2_CLK0_READ_TIME_CFG_ADR 0x00000CC0u
#define HW_ATL2_CLK1_READ_TIME_CFG_ADR 0x00000D70u
#define HW_ATL2_TSG_READ_CUR_TIME_MSK 0x00000001

#define HW_ATL2_CLK0_GPIO_CFG_ADR 0x00000CC4u
#define HW_ATL2_CLK1_GPIO_CFG_ADR 0x00000D74u
#define HW_ATL2_TSG_GPIO_IN_MONITOR_EN_SHIFT 0x00000000
#define HW_ATL2_TSG_GPIO_IN_MONITOR_EN_MSK 0x00000001
#define HW_ATL2_TSG_GPIO_IN_MODE_SHIFT 0x00000001
#define HW_ATL2_TSG_GPIO_IN_MODE_MSK 0x00000006
#define HW_ATL2_TSG_GPIO_IN_MODE_POSEDGE 0x00000000
#define HW_ATL2_TSG_GPIO_IN_MODE_NEGEDGE 0x00000002
#define HW_ATL2_TSG_GPIO_IN_MODE_TOGGLE 0x00000004

#define HW_ATL2_CLK0_EXT_CLK_CFG_ADR 0x00000CC8u
#define HW_ATL2_CLK1_EXT_CLK_CFG_ADR 0x00000D78u
#define HW_ATL2_TSG_EXT_CLK_MONITOR_EN_SHIFT 0x00000000
#define HW_ATL2_TSG_EXT_CLK_MONITOR_EN_MSK 0x00000001
#define HW_ATL2_TSG_EXT_CLK_MONITOR_PERIOD_SHIFT 0x00000001
#define HW_ATL2_TSG_EXT_CLK_MONITOR_PERIOD_MSK 0x00FFFFFE

#define HW_ATL2_CLK0_EXT_CLK_COUNT_ADR 0x00000CCCu
#define HW_ATL2_CLK1_EXT_CLK_COUNT_ADR 0x00000D7Cu

#define HW_ATL2_CLK0_GPIO_EVENT_TS_LSW_ADR 0x00000CD0u
#define HW_ATL2_CLK1_GPIO_EVENT_TS_LSW_ADR 0x00000D80u

#define HW_ATL2_CLK0_GPIO_EVENT_TS_MSW_ADR 0x00000CD4u
#define HW_ATL2_CLK1_GPIO_EVENT_TS_MSW_ADR 0x00000D84u

#define HW_ATL2_CLK0_EXT_CLK_TS_LSW_ADR 0x00000CD8u
#define HW_ATL2_CLK1_EXT_CLK_TS_LSW_ADR 0x00000D88u

#define HW_ATL2_CLK0_EXT_CLK_TS_MSW_ADR 0x00000CDCu
#define HW_ATL2_CLK1_EXT_CLK_TS_MSW_ADR 0x00000D8Cu

#define HW_ATL2_CLK0_GPIO_EVENT_GEN_TS_LSW_ADR 0x00000CE0u
#define HW_ATL2_CLK1_GPIO_EVENT_GEN_TS_LSW_ADR 0x00000D90u

#define HW_ATL2_CLK0_GPIO_EVENT_GEN_TS_MSW_ADR 0x00000CE4u
#define HW_ATL2_CLK1_GPIO_EVENT_GEN_TS_MSW_ADR 0x00000D94u

#define HW_ATL2_CLK0_GPIO_EVENT_GEN_CFG_ADR 0x00000CE8u
#define HW_ATL2_CLK1_GPIO_EVENT_GEN_CFG_ADR 0x00000D98u
#define HW_ATL2_TSG_GPIO_OUTPUT_EN_SHIFT 0x00000000
#define HW_ATL2_TSG_GPIO_OUTPUT_EN_MSK 0x00000001
#define HW_ATL2_TSG_GPIO_EVENT_MODE_SHIFT 0x00000001
#define HW_ATL2_TSG_GPIO_EVENT_MODE_MSK 0x00000006
#define HW_ATL2_TSG_GPIO_EVENT_MODE_CLEAR 0x00000000
#define HW_ATL2_TSG_GPIO_EVENT_MODE_SET 0x00000001
#define HW_ATL2_TSG_GPIO_EVENT_MODE_CLEAR_ON_TIME 0x00000002
#define HW_ATL2_TSG_GPIO_EVENT_MODE_SET_ON_TIME 0x00000003
#define HW_ATL2_TSG_GPIO_GEN_OUTPUT_EN_SHIFT 0x00000003
#define HW_ATL2_TSG_GPIO_GEN_OUTPUT_EN_MSK 0x00000008
#define HW_ATL2_TSG_GPIO_EVENT_STATUS_SHIFT 0x00000004
#define HW_ATL2_TSG_GPIO_EVENT_STATUS_MSK 0x00000010
#define HW_ATL2_TSG_GPIO_CLK_OUTPUT_EN_SHIFT 0x00000005
#define HW_ATL2_TSG_GPIO_CLK_OUTPUT_EN_MSK 0x00000020
#define HW_ATL2_TSG_GPIO_OUTPUT_BIT_POS_SHIFT 0x00000006
#define HW_ATL2_TSG_GPIO_OUTPUT_BIT_POS_MSK 0x00000fc0

#define HW_ATL2_CLK0_GPIO_EVENT_HIGH_TIME_LSW_ADR 0x00000CF0u
#define HW_ATL2_CLK1_GPIO_EVENT_HIGH_TIME_LSW_ADR 0x00000DA0u

#define HW_ATL2_CLK0_GPIO_EVENT_HIGH_TIME_MSW_ADR 0x00000CF4u
#define HW_ATL2_CLK1_GPIO_EVENT_HIGH_TIME_MSW_ADR 0x00000DA4u

#define HW_ATL2_CLK0_GPIO_EVENT_LOW_TIME_LSW_ADR 0x00000CF8u
#define HW_ATL2_CLK1_GPIO_EVENT_LOW_TIME_LSW_ADR 0x00000DA8u

#define HW_ATL2_CLK0_GPIO_EVENT_LOW_TIME_MSW_ADR 0x00000CFCu
#define HW_ATL2_CLK1_GPIO_EVENT_LOW_TIME_MSW_ADR 0x00000DACu

#define HW_ATL2_TSG_SPARE_READ_REG_ADR 0x00000D00u
#define HW_ATL2_TSG_SPARE_WRITE_REG_ADR 0x00000D04u
#define HW_ATL2_TSG_SPARE_FPGA_GPIO_CTRL_SHIFT 0x00000000u
#define HW_ATL2_TSG_SPARE_FPGA_GPIO_CTRL_MSK 0x00000FFFu
#define HW_ATL2_TSG_SPARE_FPGA_TSG0_GPIO_EVNT_O 0x00000000u
#define HW_ATL2_TSG_SPARE_FPGA_TSG0_CLK_EVNT_O 0x00000000u
#define HW_ATL2_TSG_SPARE_FPGA_TSG0_GPIO_TS_I 0x00000001u
#define HW_ATL2_TSG_SPARE_FPGA_TSG0_EXT_CLK_TS_I 0x00000002u
#define HW_ATL2_TSG_SPARE_FPGA_TSG1_GPIO_TS_I 0x00000004u
#define HW_ATL2_TSG_SPARE_FPGA_TSG1_EXT_CLK_TS_I 0x00000008u
#define HW_ATL2_TSG_SPARE_FPGA_TSG1_CLK_EVNT_O 0x00000010u
#define HW_ATL2_TSG_SPARE_FPGA_TSG1_EXT_CLK_O 0x00000020u

#define HW_ATL2_TIMESTAMPGENERATOR1_ADR 0x00000CA0u
#define HW_ATL2_TSG0_RESET_MSK 0x00000001
#define HW_ATL2_TSG1_RESET_MSK 0x00000002
#define HW_ATL2_TSG0_CLOCKENABLE_MSK 0x00000004
#define HW_ATL2_TSG1_CLOCKENABLE_MSK 0x00000008
#define HW_ATL2_TSG0_RESET_SHIFT 0
#define HW_ATL2_TSG1_RESET_SHIFT 1
#define HW_ATL2_TSG0_CLOCKENABLE_SHIFT 2
#define HW_ATL2_TSG1_CLOCKENABLE_SHIFT 3

#define HW_ATL2_TIMESTAMPGENERATOR2_ADR 0x00000CA4u
#define HW_ATL2_SETTSG0TIMERCOUNTERS_MSK 0x00000001
#define HW_ATL2_SUBTRACTTSG0TIMERCOUNTERS_MSK 0x00000002
#define HW_ATL2_ADDTSG0TIMERCOUNTERS_MSK 0x00000004
#define HW_ATL2_SETTSG1TIMERCOUNTERS_MSK 0x00000008
#define HW_ATL2_SUBTRACTTSG1TIMERCOUNTERS_MSK 0x00000010
#define HW_ATL2_ADDTSG1TIMERCOUNTERS_MSK 0x00000020
#define HW_ATL2_TSG0_LOADPERCLOCKINCREMENTVALUE_MSK 0x00000040
#define HW_ATL2_TSG1_LOADPERCLOCKINCREMENTVALUE_MSK 0x00000080
#define HW_ATL2_TSG0_DIGITALCLOCKREAD_MSK 0x00000100
#define HW_ATL2_TSG1_DIGITALCLOCKREAD_MSK 0x00000200
#define HW_ATL2_SETTSG0TIMERCOUNTERS_SHIFT 0
#define HW_ATL2_SUBTRACTTSG0TIMERCOUNTERS_SHIFT 1
#define HW_ATL2_ADDTSG0TIMERCOUNTERS_SHIFT 2
#define HW_ATL2_SETTSG1TIMERCOUNTERS_SHIFT 3
#define HW_ATL2_SUBTRACTTSG1TIMERCOUNTERS_SHIFT 4
#define HW_ATL2_ADDTSG1TIMERCOUNTERS_SHIFT 5
#define HW_ATL2_TSG0_LOADPERCLOCKINCREMENTVALUE_SHIFT 6
#define HW_ATL2_TSG1_LOADPERCLOCKINCREMENTVALUE_SHIFT 7
#define HW_ATL2_TSG0_DIGITALCLOCKREAD_SHIFT 8
#define HW_ATL2_TSG1_DIGITALCLOCKREAD_SHIFT 9

#define HW_ATL2_TSGPTPGPIOCTRL_ADR 0x00000CC4u
#define HW_ATL2_TSG0_ENCLOCKEVENTOUTPUT_MSK 0x00000001
#define HW_ATL2_TSG0_ENCLOCKEVENTOUTPUT_SHIFT 0
#define HW_ATL2_TSG0_CLOCKEVENTOUTPUTMODE_MSK 0x00000006
#define HW_ATL2_TSG0_CLOCKEVENTOUTPUTMODE_SHIFT 1
#define HW_ATL2_TSG0_SETBITPOSITION_MSK 0x000000f8
#define HW_ATL2_TSG0_SETBITPOSITION_SHIFT 3
#define HW_ATL2_TSG1_ENCLOCKEVENTOUTPUT_MSK 0x00000100
#define HW_ATL2_TSG1_ENCLOCKEVENTOUTPUT_SHIFT 8
#define HW_ATL2_TSG1_CLOCKEVENTOUTPUTMODE_MSK 0x00000600
#define HW_ATL2_TSG1_CLOCKEVENTOUTPUTMODE_SHIFT 9
#define HW_ATL2_TSG1_SETBITPOSITION_MSK 0x0000f800
#define HW_ATL2_TSG1_SETBITPOSITION_SHIFT 11
#define HW_ATL2_TSG0_ENINPUTEVENTMON_MSK 0x00010000
#define HW_ATL2_TSG0_ENINPUTEVENTMON_SHIFT 16
#define HW_ATL2_TSG0_INPUTEVENTMONMODE_MSK 0x00060000
#define HW_ATL2_TSG0_INPUTEVENTMONMODE_SHIFT 17
#define HW_ATL2_TSG1_ENINPUTEVENTMON_MSK 0x00080000
#define HW_ATL2_TSG1_ENINPUTEVENTMON_SHIFT 19
#define HW_ATL2_TSG1_INPUTEVENTMONMODE_MSK 0x00300000
#define HW_ATL2_TSG1_INPUTEVENTMONMODE_SHIFT 20
#define HW_ATL2_TSG0_GPIOUPDATEMODE_MSK 0x00c00000
#define HW_ATL2_TSG0_GPIOUPDATEMODE_SHIFT 22
#define HW_ATL2_TSG1_GPIOUPDATEMODE_MSK 0x03000000
#define HW_ATL2_TSG1_GPIOUPDATEMODE_SHIFT 24

/* Register address for bitfield Modify TSG0 fractional
 * Nano-second counter value 1
 */
#define HW_ATL2_MODIFY_PTP_FRAC_NS_COUNTER_VAL1_ADR 0x00000CA8
/* Register address for bitfield Modify TSG0 Nano-second counter value 0 */
#define HW_ATL2_MODIFY_TSG0_NS_COUNTER_VAL0_ADR 0x00000CAC
/* Register address for bitfield Modify TSG0 Nano-second counter value 1 */
#define HW_ATL2_MODIFY_TSG0_NS_COUNTER_VAL1_ADR 0x00000CB0

/* Register address for bitfield Modify PTP fractional
 * Nano-second counter value 1
 */
#define HW_ATL2_MODIFY_TSG1_FRAC_NS_COUNTER_VAL1_ADR 0x00000CF8
/* Register address for bitfield Modify PTM Nano-second counter value 0 */
#define HW_ATL2_MODIFY_TSG1_NS_COUNTER_VAL0_ADR 0x00000CFC
/* Register address for bitfield Modify PTM Nano-second counter value 1 */
#define HW_ATL2_MODIFY_TSG1_NS_COUNTER_VAL1_ADR 0x00000D00

/* Register address for bitfield Modify PTP counter increment value */
#define  HW_ATL2_TSG0_COUNTERINCREMENTVALUE_ADR 0x00000CB4

/* Register address for bitfield Modify PTM counter increment value */
#define  HW_ATL2_TSG1_COUNTERINCREMENTVALUE_ADR 0x00000D04

/* Register address for bitfield digital clock nanosecond count bits 31:0 */
#define HW_ATL2_TSG0_CLOCK_NS_COUNTBIT_LSW_ADR 0x00000CBC

/* Register address for bitfield digital clock nanosecond count bits 63:32 */
#define HW_ATL2_TSG0_CLOCK_NS_COUNTBIT_MSW_ADR 0x00000CC0

/* Register address for bitfield PTM digital clock
 * nanosecond count bits 31:0
 */
#define HW_ATL2_TSG1_CLOCK_NS_COUNTBIT_LSW_ADR 0x00000D0C

/* Register address for bitfield PTM digital clock
 * nanosecond count bits 63:32
 */
#define HW_ATL2_TSG1_CLOCK_NS_COUNTBIT_MSW_ADR 0x00000D10

/* Register address for bitfield TSG PTP GPIO
 * event timestamp nanosecond bits 31:0
 */
#define HW_ATL2_TSG0_GPIOEVENTTS_LSW_ADR 0x00000CD0

/* Register address for bitfield TSG PTP GPIO
 * event timestamp nanosecond bits 63:32
 */
#define HW_ATL2_TSG0_GPIOEVENTTS_MSW_ADR 0x00000CD4

/* Register address for bitfield TSG PTM GPIO
 * event timestamp nanosecond bits 31:0
 */
#define HW_ATL2_TSG1_GPIOEVENTTS_LSW_ADR 0x00000D0C

/* Register address for bitfield TSG PTM GPIO
 * event timestamp nanosecond bits 63:32
 */
#define HW_ATL2_TSG1_GPIOEVENTTS_MSW_ADR 0x00000D10

/* PCIE Extended tag enable Bitfield Definitions
 */
#define HW_ATL2_PHI_EXT_TAG_EN_ADR 0x00001000
#define HW_ATL2_PHI_EXT_TAG_EN_MSK 0x00000020
#define HW_ATL2_PHI_EXT_TAG_EN_MSKN 0xFFFFFFDF
#define HW_ATL2_PHI_EXT_TAG_EN_SHIFT 5
#define HW_ATL2_PHI_EXT_TAG_EN_WIDTH 1
#define HW_ATL2_PHI_EXT_TAG_EN_DEFAULT 0x0

/* PCI core control register */
#define HW_ATL2_PCI_REG_CONTROL6_ADR 0x1014u

/* Launch time control register */
#define HW_ATL2_LT_CTRL_ADR 0x00007a1c

#define HW_ATL2_LT_CTRL_AVB_LEN_CMP_TRSHLD_MSK 0xFFFF0000
#define HW_ATL2_LT_CTRL_AVB_LEN_CMP_TRSHLD_SHIFT 16

#define HW_ATL2_LT_CTRL_CLK_RATIO_MSK 0x0000FF00
#define HW_ATL2_LT_CTRL_CLK_RATIO_SHIFT 8
#define HW_ATL2_LT_CTRL_CLK_RATIO_QUATER_SPEED 4
#define HW_ATL2_LT_CTRL_CLK_RATIO_HALF_SPEED 2
#define HW_ATL2_LT_CTRL_CLK_RATIO_FULL_SPEED 1

#define HW_ATL2_LT_CTRL_25G_MODE_SUPPORT_MSK 0x00000008
#define HW_ATL2_LT_CTRL_25G_MODE_SUPPORT_SHIFT 3

#define HW_ATL2_LT_CTRL_LINK_SPEED_MSK 0x00000007
#define HW_ATL2_LT_CTRL_LINK_SPEED_SHIFT 0

/* FPGA VER register */
#define HW_ATL2_FPGA_VER_ADR 0x000000f4
#define HW_ATL2_FPGA_VER_U32(mj, mi, bl, rv) \
	((((mj) & 0xff) << 24) | \
	 (((mi) & 0xff) << 16) | \
	 (((bl) & 0xff) << 8) | \
	 (((rv) & 0xff) << 0))

/* ahb_mem_addr{f}[31:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "ahb_mem_addr{f}[31:0]".
 * Parameter: filter {f} | stride size 0x10 | range [0, 127]
 * PORT="ahb_mem_addr{f}[31:0]"
 */

/* Register address for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_ADR(filter) \
	(0x00014000u + (filter) * 0x10)
/* Bitmask for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_MSK 0xFFFFFFFFu
/* Inverted bitmask for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_MSKN 0x00000000u
/* Lower bit position of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_SHIFT 0
/* Width of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_WIDTH 31
/* Default value of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_REQ_TAG_DEFAULT 0x0

/* Register address for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_ADR(filter) \
	(0x00014004u + (filter) * 0x10)
/* Bitmask for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_MSK 0xFFFFFFFFu
/* Inverted bitmask for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_MSKN 0x00000000u
/* Lower bit position of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_SHIFT 0
/* Width of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_WIDTH 31
/* Default value of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_TAG_MASK_DEFAULT 0x0

/* Register address for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_ACTN_ADR(filter) \
	(0x00014008u + (filter) * 0x10)
/* Bitmask for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_ACTN_MSK 0x000007FFu
/* Inverted bitmask for bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_ACTN_MSKN 0xFFFFF800u
/* Lower bit position of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_ACTN_SHIFT 0
/* Width of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_ACTN_WIDTH 10
/* Default value of bitfield ahb_mem_addr{f}[31:0] */
#define HW_ATL2_RPF_ACT_RSLVR_ACTN_DEFAULT 0x0

/* rpf_rec_tab_en[15:0] Bitfield Definitions
 * Preprocessor definitions for the bitfield "rpf_rec_tab_en[15:0]".
 * PORT="pif_rpf_rec_tab_en[15:0]"
 */
/* Register address for bitfield rpf_rec_tab_en[15:0] */
#define HW_ATL2_RPF_REC_TAB_EN_ADR 0x00006ff0u
/* Bitmask for bitfield rpf_rec_tab_en[15:0] */
#define HW_ATL2_RPF_REC_TAB_EN_MSK 0x0000FFFFu
/* Inverted bitmask for bitfield rpf_rec_tab_en[15:0] */
#define HW_ATL2_RPF_REC_TAB_EN_MSKN 0xFFFF0000u
/* Lower bit position of bitfield rpf_rec_tab_en[15:0] */
#define HW_ATL2_RPF_REC_TAB_EN_SHIFT 0
/* Width of bitfield rpf_rec_tab_en[15:0] */
#define HW_ATL2_RPF_REC_TAB_EN_WIDTH 16
/* Default value of bitfield rpf_rec_tab_en[15:0] */
#define HW_ATL2_RPF_REC_TAB_EN_DEFAULT 0x0

/* Register address for firmware shared input buffer */
#define HW_ATL2_MIF_SHARED_BUFFER_IN_ADR(dword) (0x00012000U + (dword) * 0x4U)
/* Register address for firmware shared output buffer */
#define HW_ATL2_MIF_SHARED_BUFFER_OUT_ADR(dword) (0x00013000U + (dword) * 0x4U)

/* pif_host_finished_buf_wr_i Bitfield Definitions
 * Preprocessor definitions for the bitfield "pif_host_finished_buf_wr_i".
 * PORT="pif_host_finished_buf_wr_i"
 */
/* Register address for bitfield rpif_host_finished_buf_wr_i */
#define HW_ATL2_MIF_HOST_FINISHED_WRITE_ADR 0x00000e00u
/* Bitmask for bitfield pif_host_finished_buf_wr_i */
#define HW_ATL2_MIF_HOST_FINISHED_WRITE_MSK 0x00000001u
/* Inverted bitmask for bitfield pif_host_finished_buf_wr_i */
#define HW_ATL2_MIF_HOST_FINISHED_WRITE_MSKN 0xFFFFFFFEu
/* Lower bit position of bitfield pif_host_finished_buf_wr_i */
#define HW_ATL2_MIF_HOST_FINISHED_WRITE_SHIFT 0
/* Width of bitfield pif_host_finished_buf_wr_i */
#define HW_ATL2_MIF_HOST_FINISHED_WRITE_WIDTH 1
/* Default value of bitfield pif_host_finished_buf_wr_i */
#define HW_ATL2_MIF_HOST_FINISHED_WRITE_DEFAULT 0x0

/* pif_mcp_finished_buf_rd_i Bitfield Definitions
 * Preprocessor definitions for the bitfield "pif_mcp_finished_buf_rd_i".
 * PORT="pif_mcp_finished_buf_rd_i"
 */
/* Register address for bitfield pif_mcp_finished_buf_rd_i */
#define HW_ATL2_MIF_MCP_FINISHED_READ_ADR 0x00000e04u
/* Bitmask for bitfield pif_mcp_finished_buf_rd_i */
#define HW_ATL2_MIF_MCP_FINISHED_READ_MSK 0x00000001u
/* Inverted bitmask for bitfield pif_mcp_finished_buf_rd_i */
#define HW_ATL2_MIF_MCP_FINISHED_READ_MSKN 0xFFFFFFFEu
/* Lower bit position of bitfield pif_mcp_finished_buf_rd_i */
#define HW_ATL2_MIF_MCP_FINISHED_READ_SHIFT 0
/* Width of bitfield pif_mcp_finished_buf_rd_i */
#define HW_ATL2_MIF_MCP_FINISHED_READ_WIDTH 1
/* Default value of bitfield pif_mcp_finished_buf_rd_i */
#define HW_ATL2_MIF_MCP_FINISHED_READ_DEFAULT 0x0

/* Register address for bitfield pif_mcp_boot_reg */
#define HW_ATL2_MIF_BOOT_REG_ADR 0x00003040u

#define HW_ATL2_MCP_HOST_REQ_INT_READY BIT(0)

#define HW_ATL2_MCP_HOST_REQ_INT_ADR 0x00000F00u
#define HW_ATL2_MCP_HOST_REQ_INT_SET_ADR 0x00000F04u
#define HW_ATL2_MCP_HOST_REQ_INT_CLR_ADR 0x00000F08u

/* Preprocessor definitions for the bitfield "PTP EXT GPIO TS SEL".
 *
 * Type: R/W
 *
 * Notes: Select one out of 24 GPIO PIN values to be used for triggering
 * timestamps in the PTP module. It can be either the external input or the
 * f/w driven GPIO output - depending on GPIO Input Enable.
 * Note that the GPIO value provided to PTP is forced to 0 if an invalid GPIO
 * PIN is configured (24...31).
 *
 * PORT="pif_ptp_ext_gpio_ts_sel_i[4:0]"
 */

/* Register address for bitfield PTP EXT GPIO TS SEL */
#define  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_ADR 0x00003664
/* Bitmask for bitfield PTP EXT GPIO TS SEL */
#define  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_MSK 0x00001F00
/* Inverted bitmask for bitfield PTP EXT GPIO TS SEL */
#define  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_MSKN 0xFFFFE0FF
/* Lower bit position of bitfield PTP EXT GPIO TS SEL */
#define  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_SHIFT 8
/* Width of bitfield PTP EXT GPIO TS SEL */
#define  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_WIDTH 5
/* Default value of bitfield PTP EXT GPIO TS SEL */
#define  HW_ATL2_TSG0_EXT_GPIO_TS_INPUT_SEL_DEFAULT 0x0

/* Preprocessor definitions for the bitfield "TSG EXT GPIO TS SEL".
 *
 * Type: R/W
 *
 * Notes: Select one out of 24 GPIO PIN values to be used for triggering
 * timestamps in the TSG module. It can be either the external input or
 * the f/w driven GPIO output - depending on GPIO Input Enable.
 * Note that the GPIO value provided to TSG is forced to 0 if an invalid
 * GPIO PIN is configured (24...31).
 *
 *   PORT="pif_tsg_ext_gpio_ts_sel_i[4:0]"
 */

/* Register address for bitfield TSG EXT GPIO TS SEL */
#define  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_ADR 0x00003660
/* Bitmask for bitfield TSG EXT GPIO TS SEL */
#define  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_MSK 0x00001F00
/* Inverted bitmask for bitfield TSG EXT GPIO TS SEL */
#define  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_MSKN 0xFFFFE0FF
/* Lower bit position of bitfield TSG EXT GPIO TS SEL */
#define  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_SHIFT 8
/* Width of bitfield TSG EXT GPIO TS SEL */
#define  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_WIDTH 5
/* Default value of bitfield TSG EXT GPIO TS SEL */
#define  HW_ATL2_TSG1_EXT_GPIO_TS_INPUT_SEL_DEFAULT 0x0

/* COM PTP EXT CLK TS SEL Bitfield Definitions
 *
 * Preprocessor definitions for the bitfield "PTP EXT CLK TS SEL".
 *
 * Type: R/W
 *
 * Notes: Select one out of 24 GPIO PIN values to be used for the clock
 * source related to timestamping in the PTP module. It can be either the
 * external input or the f/w driven GPIO output - depending on GPIO Input
 * Enable.
 * Note that the GPIO value provided to PTP is forced to 0 if an invalid GPIO
 * PIN is configured (24...31).
 *
 * PORT="pif_ptp_ext_clk_ts_sel_i[4:0]"
 */

/* Register address for bitfield PTP EXT CLK TS SEL */
#define  HW_ATL2_TSG0_TS_INPUT_SEL_ADR 0x00003664
/* Bitmask for bitfield PTP EXT CLK TS SEL */
#define  HW_ATL2_TSG0_TS_INPUT_SEL_MSK 0x001F0000
/* Inverted bitmask for bitfield PTP EXT CLK TS SEL */
#define  HW_ATL2_TSG0_TS_INPUT_SEL_MSKN 0xFFE0FFFF
/* Lower bit position of bitfield PTP EXT CLK TS SEL */
#define  HW_ATL2_TSG0_TS_INPUT_SEL_SHIFT 16
/* Width of bitfield PTP EXT CLK TS SEL */
#define  HW_ATL2_TSG0_TS_INPUT_SEL_WIDTH 5
/* Default value of bitfield PTP EXT CLK TS SEL */
#define  HW_ATL2_TSG0_TS_INPUT_SEL_DEFAULT 0x0

/* Preprocessor definitions for the bitfield "GPIO{P} Special Mode".
 * Parameter: pin {P} | stride size 0x4 | range [0, 23]
 * Type: R/W
 *
 * Notes: Select GPIO0 pin usage
 * 3: Atlantic MDC
 * 2: Atlantic TC0 Clk Out
 * 1: Unused
 * 0: Use PIN as Atlantic GPIO0
 *
 * PORT="pif_gpio_special_mode0_i[1:0]"
 */

/* Register address for bitfield GPIO{P} Special Mode */
#define  HW_ATL2_GPIO_PIN_SPEC_MODE_ADR(pin) (0x00003698 + (pin) * 0x4)
/* Bitmask for bitfield GPIO{P} Special Mode */
#define  HW_ATL2_GPIO_PIN_SPEC_MODE_MSK 0x0000000C
/* Inverted bitmask for bitfield GPIO{P} Special Mode */
#define  HW_ATL2_GPIO_PIN_SPEC_MODE_MSKN 0xFFFFFFF3
/* Lower bit position of bitfield GPIO{P} Special Mode */
#define  HW_ATL2_GPIO_PIN_SPEC_MODE_SHIFT 2
/* Width of bitfield GPIO{P} Special Mode */
#define  HW_ATL2_GPIO_PIN_SPEC_MODE_WIDTH 2
/* Default value of bitfield GPIO{P} Special Mode */
#define  HW_ATL2_GPIO_PIN_SPEC_MODE_DEFAULT 0x0

#define HW_ATL2_GPIO_PIN_SPEC_MODE_TSG1_EVENT_OUTPUT 0
#define HW_ATL2_GPIO_PIN_SPEC_MODE_TSG0_EVENT_OUTPUT 2
#define HW_ATL2_GPIO_PIN_SPEC_MODE_GPIO 3

/* Preprocessor definitions for the bitfield
 * "Primary Timestamp Clock Source Selection".
 */

/* Register address for bitfield */
#define  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_ADR 0x0000454C
/* Bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_MSK 0xFFFF0000
/* Inverted bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_MSKN 0x0000FFFF
/* Lower bit position of bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_SHIFT 16
/* Width of bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_INC_VAL_WIDTH 16

/* Preprocessor definitions for the bitfield
 * "Primary Timestamp Clock Source Selection".
 */

/* Register address for bitfield */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_ADR 0x0000454C
/* Bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_MSK 0x00003F00
/* Inverted bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_MSKN 0xFFFFC0FF
/* Lower bit position of bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_SHIFT 8
/* Width of bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_PERIOD_WIDTH 6

/* Preprocessor definitions for the bitfield
 * "Primary Timestamp Clock Source Selection".
 */

/* Register address for bitfield */
#define  HW_ATL2_FIFO_312P_NS_INC_VAL_ADR 0x0000454C
/* Bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_NS_INC_VAL_MSK 0x0000003F
/* Inverted bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_NS_INC_VAL_MSKN 0xFFFFFFC0
/* Lower bit position of bitfield  */
#define  HW_ATL2_FIFO_312P_NS_INC_VAL_SHIFT 0
/* Width of bitfield  */
#define  HW_ATL2_FIFO_312P_NS_INC_VAL_WIDTH 6

/* Preprocessor definitions for the bitfield
 * "Primary Timestamp Clock Source Selection".
 */

/* Register address for bitfield */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_ADR 0x00004550
/* Bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_MSK 0x0000FFFF
/* Inverted bitmask for bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_MSKN 0xFFFF0000
/* Lower bit position of bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_SHIFT 0
/* Width of bitfield  */
#define  HW_ATL2_FIFO_312P_FRAC_NS_CORR_VAL_WIDTH 16

/* Host Interrupt Request CLR */
#define HW_ATL2_CLEAR_HOST_IRQ_REG 0xF08
/* Clear Host Interrupt Request Mask */
#define HW_ATL2_HOST_IRQ_MASK 0x1
/* Shared Buffer MMIO address */
#define HW_ATL2_SHMEM_BUF_MMIO_ADDR 0x10000
/* MCP/Host Shared Buffer Control 1 */
#define HW_ATL2_CONFIRM_SHARED_BUF_REG 0x0E00
/* Host Finished Shared Buffer Write */
#define HW_ATL2_CONFIRM_SHARED_BUF_MASK 0x1

#endif /* HW_ATL2_LLH_INTERNAL_H */
