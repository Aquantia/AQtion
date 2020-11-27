/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Marvell Technology */

#ifndef _AQ_XDP_H_
#define _AQ_XDP_H_

#ifdef HAS_XDP

int aq_xdp_setup(struct aq_nic_s *nic, struct bpf_prog *prog);

int aq_xdp_execute(struct aq_ring_s *rx_ring, struct xdp_buff *xdp);

int aq_xdp_xmit(struct net_device *dev, int n,
		struct xdp_frame **frames, u32 flags);
		
int aq_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags);

#endif
#endif
