/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2018 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM atlantic

#if !defined(_AQ_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _AQ_TRACE_H

#include <linux/tracepoint.h>
#include <linux/skbuff.h>
#include <linux/version.h>


#define DESCR_FIELD(DESCR, BIT_BEGIN, BIT_END) \
	((DESCR >> BIT_END) &\
		(BIT(BIT_BEGIN - BIT_END + 1) - 1))

TRACE_EVENT(aq_rx_descr,
	TP_PROTO(int ring_idx, unsigned int pointer, u64 descr[2]),
	TP_ARGS(ring_idx, pointer, descr),
	TP_STRUCT__entry(
		__field(unsigned int, ring_idx)
		__field(unsigned int, pointer)
		__field(u8, dd)
		__field(u8, eop)
		__field(u8, rx_stat)
		__field(u8, rx_estat)
		__field(u8, rsc_cnt)
		__field(u16, pkt_len)
		__field(u16, next_desp)
		__field(u16, vlan_tag)

		__field(u8, rss_type)
		__field(u8, pkt_type)
		__field(u8, rsvd)
		__field(u8, rx_cntl)
		__field(u8, sph)
		__field(u16, hdr_len)
		__field(u32, rss_hash)

	),
	TP_fast_assign(
		__entry->ring_idx = ring_idx;
		__entry->pointer = pointer;
		__entry->rss_hash = DESCR_FIELD(descr[0], 63, 32);
		__entry->hdr_len =  DESCR_FIELD(descr[0], 31, 22);
		__entry->sph = DESCR_FIELD(descr[0], 21, 21);
		__entry->rx_cntl = DESCR_FIELD(descr[0], 20, 19);
		__entry->rsvd = DESCR_FIELD(descr[0], 18, 12);
		__entry->pkt_type = DESCR_FIELD(descr[0], 11, 4);
		__entry->rss_type = DESCR_FIELD(descr[0], 3, 0);

		__entry->vlan_tag = DESCR_FIELD(descr[1], 63, 48);
		__entry->next_desp = DESCR_FIELD(descr[1], 47, 32);
		__entry->pkt_len = DESCR_FIELD(descr[1], 31, 16);
		__entry->rsc_cnt = DESCR_FIELD(descr[1], 15, 12);
		__entry->rx_estat = DESCR_FIELD(descr[1], 11, 6);
		__entry->rx_stat = DESCR_FIELD(descr[1], 5, 2);
		__entry->eop = DESCR_FIELD(descr[1], 1, 1);
		__entry->dd = DESCR_FIELD(descr[1], 0, 0);
	),
	TP_printk("ring=%d descr=%u rss_hash=0x%x hdr_len=%u sph=%u rx_cntl=%u rsvd=0x%x pkt_type=%u rss_type=%u vlan_tag=%u next_desp=%u pkt_len=%u rsc_cnt=%u rx_estat=0x%x rx_stat=0x%x eop=%u dd=%u",
		  __entry->ring_idx, __entry->pointer, __entry->rss_hash,
		  __entry->hdr_len, __entry->sph, __entry->rx_cntl,
		  __entry->rsvd, __entry->pkt_type, __entry->rss_type,
		  __entry->vlan_tag, __entry->next_desp, __entry->pkt_len,
		  __entry->rsc_cnt, __entry->rx_estat, __entry->rx_stat,
		  __entry->eop, __entry->dd)
);

TRACE_EVENT(aq_tx_descr,
	TP_PROTO(int ring_idx, unsigned int pointer, u64 descr[2]),
	TP_ARGS(ring_idx, pointer, descr),
	TP_STRUCT__entry(
		__field(unsigned int, ring_idx)
		__field(unsigned int, pointer)
		/* Tx Descriptor */
		__field(u64, data_buf_addr)
		__field(u32, pay_len)
		__field(u8, ct_en)
		__field(u8, ct_idx)
		__field(u16, rsvd2)
		__field(u8, tx_cmd)
		__field(u8, eop)
		__field(u8, dd)
		__field(u16, buf_len)
		__field(u8, rsvd1)
		__field(u8, des_typ)
	),
	TP_fast_assign(
		__entry->ring_idx = ring_idx;
		__entry->pointer = pointer;
		__entry->data_buf_addr = descr[0];
		__entry->pay_len = DESCR_FIELD(descr[1], 63, 46);
		__entry->ct_en =  DESCR_FIELD(descr[1], 45, 45);
		__entry->ct_idx = DESCR_FIELD(descr[1], 44, 44);
		__entry->rsvd2 = DESCR_FIELD(descr[1], 43, 30);
		__entry->tx_cmd = DESCR_FIELD(descr[1], 29, 22);
		__entry->eop = DESCR_FIELD(descr[1], 21, 21);
		__entry->dd = DESCR_FIELD(descr[1], 20, 20);
		__entry->buf_len = DESCR_FIELD(descr[1], 19, 4);
		__entry->rsvd1 = DESCR_FIELD(descr[1], 3, 3);
		__entry->des_typ = DESCR_FIELD(descr[1], 2, 0);

	),
	TP_printk("ring=%d descr=%u pay_len=%u ct_en=%u ct_idx=%u rsvd2=0x%x tx_cmd=0x%x eop=%u dd=%u buf_len=%u rsvd1=%u des_typ=0x%x",
		  __entry->ring_idx, __entry->pointer, __entry->pay_len,
		  __entry->ct_en, __entry->ct_idx, __entry->rsvd2,
		  __entry->tx_cmd, __entry->eop, __entry->dd, __entry->buf_len,
		  __entry->rsvd1, __entry->des_typ)
);


TRACE_EVENT(aq_tx_context_descr,
	TP_PROTO(int ring_idx, unsigned int pointer, u64 descr[2]),
	TP_ARGS(ring_idx, pointer, descr),
	TP_STRUCT__entry(
		__field(unsigned int, ring_idx)
		__field(unsigned int, pointer)
		/* Tx Context Descriptor */
		__field(u16, out_len)
		__field(u8, tun_len)
		__field(u64, resvd3)
		__field(u16, mss_len)
		__field(u8, l4_len)
		__field(u8, l3_len)
		__field(u8, l2_len)
		__field(u8, ct_cmd)
		__field(u16, vlan_tag)
		__field(u8, ct_idx)
		__field(u8, des_typ)
	),
	TP_fast_assign(
		__entry->ring_idx = ring_idx;
		__entry->pointer = pointer;
		__entry->out_len = DESCR_FIELD(descr[0], 63, 48);
		__entry->tun_len = DESCR_FIELD(descr[0], 47, 40);
		__entry->resvd3 = DESCR_FIELD(descr[0], 39, 0);
		__entry->mss_len = DESCR_FIELD(descr[1], 63, 48);
		__entry->l4_len = DESCR_FIELD(descr[1], 47, 40);
		__entry->l3_len = DESCR_FIELD(descr[1], 39, 31);
		__entry->l2_len = DESCR_FIELD(descr[1], 30, 24);
		__entry->ct_cmd = DESCR_FIELD(descr[1], 23, 20);
		__entry->vlan_tag = DESCR_FIELD(descr[1], 19, 4);
		__entry->ct_idx = DESCR_FIELD(descr[1], 3, 3);
		__entry->des_typ = DESCR_FIELD(descr[1], 2, 0);
	),
	TP_printk("ring=%d descr=%u out_len=%u tun_len=%u resvd3=%llu mss_len=%u l4_len=%u l3_len=%u l2_len=0x%x ct_cmd=%u vlan_tag=%u ct_idx=%u des_typ=0x%x",
		  __entry->ring_idx, __entry->pointer, __entry->out_len,
		  __entry->tun_len, __entry->resvd3, __entry->mss_len,
		  __entry->l4_len, __entry->l3_len, __entry->l2_len,
		  __entry->ct_cmd, __entry->vlan_tag, __entry->ct_idx,
		  __entry->des_typ)
);


void trace_aq_tx_descriptor(int ring_idx, unsigned int pointer, u64 descr[2]);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0) || RHEL_RELEASE_CODE
#define SKB_CSUM_LEVEL(SKB) ((SKB)->csum_level)
#else
#define SKB_CSUM_LEVEL(SKB) 0
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0) || RHEL_RELEASE_CODE
#define SKB_HASH(SKB) ((SKB)->hash)
#else
#define SKB_HASH(SKB) ((SKB)->rxhash)
#endif
TRACE_EVENT(aq_produce_skb,
	TP_PROTO(int ring_idx, struct sk_buff *skb),
	TP_ARGS(ring_idx, skb),
	TP_STRUCT__entry(
		__field(unsigned int, ring_idx)
		__field(unsigned int, len)
		__field(u8, ip_summed)
		__field(u8, csum_level)
		__field(u16, vlan_tci)
		__field(u32, hash)
	),
	TP_fast_assign(
		__entry->ring_idx = ring_idx;
		__entry->len = skb->len;
		__entry->ip_summed = skb->ip_summed;
		__entry->csum_level = SKB_CSUM_LEVEL(skb);
		__entry->vlan_tci = skb->vlan_tci;
		__entry->hash = SKB_HASH(skb);
	),
	TP_printk("ring=%d len=%d ip_summed=%d csum_level=%d vlan_tci=0x%x rxhash=0x%x",
		  __entry->ring_idx, __entry->len, __entry->ip_summed,
		  __entry->csum_level, __entry->vlan_tci, __entry->hash)
);
#undef SKB_CSUM_LEVEL
#undef SKB_HASH

#endif /* _AQ_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef  TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE aq_trace
#include <trace/define_trace.h>
