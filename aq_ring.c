/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_ring.c: Definition of functions for Rx/Tx rings. */

#include "aq_ring.h"
#include "aq_nic.h"
#include "aq_hw.h"
#include "aq_hw_utils.h"

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

static inline void aq_free_rxpage(struct aq_rxpage *rxpage, struct device *dev)
{
	unsigned len = PAGE_SIZE << rxpage->order;

	dma_unmap_page(dev, rxpage->daddr, len, DMA_FROM_DEVICE);

	/* Drop the ref for being in the ring. */
	__free_pages(rxpage->page, rxpage->order);
	rxpage->page = NULL;
}

static int aq_get_rxpage(struct aq_rxpage *rxpage, unsigned order,
	struct device *dev)
{
	struct page *page;
	dma_addr_t daddr;
	int ret = -ENOMEM;

	page = dev_alloc_pages(order);
	if (unlikely(!page))
		goto err_exit;

	daddr = dma_map_page(dev, page, 0, PAGE_SIZE << order, DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(dev, daddr)))
		goto free_page;

	rxpage->page = page;
	rxpage->daddr = daddr;
	rxpage->order = order;
	rxpage->pg_off = 0;

	return 0;

free_page:
	__free_pages(page, order);
err_exit:

	return ret;
}

static int aq_get_rxpages(struct aq_ring_s *self, struct aq_ring_buff_s *rxbuf, int order)
{
	int ret;

	if (rxbuf->rxdata.page) {
		/* One means ring is the only user and can reuse */
		if (page_ref_count(rxbuf->rxdata.page) > 1) {
			/* Try reuse buffer */
			rxbuf->rxdata.pg_off += AQ_CFG_RX_FRAME_MAX;
			if (rxbuf->rxdata.pg_off + AQ_CFG_RX_FRAME_MAX <=
				(PAGE_SIZE << order)) {
				self->stats.rx.pg_flips++;
			} else {
				/* Buffer exhausted. We have other users and
				 * should release this page and realloc
				 */
				aq_free_rxpage(&rxbuf->rxdata,
					       aq_nic_get_dev(self->aq_nic));
				self->stats.rx.pg_losts++;
			}
		} else {
			rxbuf->rxdata.pg_off = 0;
			self->stats.rx.pg_reuses++;
		}
	}

	if (!rxbuf->rxdata.page) {
		ret = aq_get_rxpage(&rxbuf->rxdata, order,
				  aq_nic_get_dev(self->aq_nic));
		return ret;
	}

	return 0;
}

static struct aq_ring_s *aq_ring_alloc(struct aq_ring_s *self,
				       struct aq_nic_s *aq_nic)
{
	int err = 0;

	self->buff_ring =
		kcalloc(self->size, sizeof(struct aq_ring_buff_s), GFP_KERNEL);

	if (!self->buff_ring) {
		err = -ENOMEM;
		goto err_exit;
	}
	self->dx_ring = dma_alloc_coherent(aq_nic_get_dev(aq_nic),
						self->size * self->dx_size,
						&self->dx_ring_pa, GFP_KERNEL);
	if (!self->dx_ring) {
		err = -ENOMEM;
		goto err_exit;
	}

err_exit:
	if (err < 0) {
		aq_ring_free(self);
		self = NULL;
	}
	return self;
}

struct aq_ring_s *aq_ring_tx_alloc(struct aq_ring_s *self,
				   struct aq_nic_s *aq_nic,
				   unsigned int idx,
				   struct aq_nic_cfg_s *aq_nic_cfg)
{
	int err = 0;

	self->aq_nic = aq_nic;
	self->idx = idx;
	self->size = aq_nic_cfg->txds;
	self->dx_size = aq_nic_cfg->aq_hw_caps->txd_size;

	self = aq_ring_alloc(self, aq_nic);
	if (!self) {
		err = -ENOMEM;
		goto err_exit;
	}

err_exit:
	if (err < 0) {
		aq_ring_free(self);
		self = NULL;
	}
	return self;
}

struct aq_ring_s *aq_ring_rx_alloc(struct aq_ring_s *self,
				   struct aq_nic_s *aq_nic,
				   unsigned int idx,
				   struct aq_nic_cfg_s *aq_nic_cfg)
{
	int err = 0;

	self->aq_nic = aq_nic;
	self->idx = idx;
	self->size = aq_nic_cfg->rxds;
	self->dx_size = aq_nic_cfg->aq_hw_caps->rxd_size;
	self->page_order = fls(AQ_CFG_RX_FRAME_MAX / PAGE_SIZE +
			(AQ_CFG_RX_FRAME_MAX % PAGE_SIZE ? 1 : 0)) - 1;
	if (aq_nic_cfg->rxpageorder > self->page_order)
		self->page_order = aq_nic_cfg->rxpageorder;

	self = aq_ring_alloc(self, aq_nic);
	if (!self) {
		err = -ENOMEM;
		goto err_exit;
	}

err_exit:
	if (err < 0) {
		aq_ring_free(self);
		self = NULL;
	}
	return self;
}

int aq_ring_init(struct aq_ring_s *self)
{
	self->hw_head = 0;
	self->sw_head = 0;
	self->sw_tail = 0;
	return 0;
}

static inline bool aq_ring_dx_in_range(unsigned int h, unsigned int i,
				       unsigned int t)
{
	return (h < t) ? ((h < i) && (i < t)) : ((h < i) || (i < t));
}

void aq_ring_update_queue_state(struct aq_ring_s *ring)
{
	if (aq_ring_avail_dx(ring) <= AQ_CFG_SKB_FRAGS_MAX)
		aq_ring_queue_stop(ring);
	else if (aq_ring_avail_dx(ring) > AQ_CFG_RESTART_DESC_THRES)
		aq_ring_queue_wake(ring);
}

void aq_ring_queue_wake(struct aq_ring_s *ring)
{
	struct net_device *ndev = aq_nic_get_ndev(ring->aq_nic);

	if (__netif_subqueue_stopped(ndev, ring->idx)) {
		netif_wake_subqueue(ndev, ring->idx);
		ring->stats.tx.queue_restarts++;
	}
}

void aq_ring_queue_stop(struct aq_ring_s *ring)
{
	struct net_device *ndev = aq_nic_get_ndev(ring->aq_nic);

	if (!__netif_subqueue_stopped(ndev, ring->idx))
		netif_stop_subqueue(ndev, ring->idx);
}

bool aq_ring_tx_clean(struct aq_ring_s *self)
{
	struct device *dev = aq_nic_get_dev(self->aq_nic);
	unsigned int budget = AQ_CFG_TX_CLEAN_BUDGET;

	for (; self->sw_head != self->hw_head && budget--;
		self->sw_head = aq_ring_next_dx(self, self->sw_head)) {
		struct aq_ring_buff_s *buff = &self->buff_ring[self->sw_head];

		if (likely(buff->is_mapped)) {
			if (unlikely(buff->is_sop)) {
				if (!buff->is_eop &&
				    buff->eop_index != 0xffffU &&
				    (!aq_ring_dx_in_range(self->sw_head,
						buff->eop_index,
						self->hw_head)))
					break;

				dma_unmap_single(dev, buff->pa, buff->len,
						 DMA_TO_DEVICE);
			} else {
				dma_unmap_page(dev, buff->pa, buff->len,
					       DMA_TO_DEVICE);
			}
		}

		if (unlikely(buff->is_eop))
			dev_kfree_skb_any(buff->skb);

		buff->pa = 0U;
		buff->eop_index = 0xffffU;
	}

	return !!budget;
}

#define AQ_SKB_ALIGN SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
int aq_ring_rx_clean(struct aq_ring_s *self,
		     struct napi_struct *napi,
		     int *work_done,
		     int budget)
{
	struct net_device *ndev = aq_nic_get_ndev(self->aq_nic);
	bool is_rsc_completed = true;
	int err = 0;

	for (; (self->sw_head != self->hw_head) && budget;
		self->sw_head = aq_ring_next_dx(self, self->sw_head),
		--budget, ++(*work_done)) {
		struct aq_ring_buff_s *buff = &self->buff_ring[self->sw_head];
		struct aq_ring_buff_s *buff_ = NULL;
		struct sk_buff *skb = NULL;
		unsigned int next_ = 0U;
		unsigned int i = 0U;
		u16 hdr_len;

		if (buff->is_error) {
			continue;
		}

		if (buff->is_cleaned)
			continue;

		rmb();

		if (!buff->is_eop) {
			for (next_ = buff->next,
			     buff_ = &self->buff_ring[next_]; true;
			     next_ = buff_->next,
			     buff_ = &self->buff_ring[next_]) {
				is_rsc_completed =
					aq_ring_dx_in_range(self->sw_head,
							    next_,
							    self->hw_head);

				if (unlikely(!is_rsc_completed)) {
					is_rsc_completed = false;
					break;
				}

				if (buff_->is_eop)
					break;
			}

			if (!is_rsc_completed) {
				err = 0;
				goto err_exit;
			}
		}

		dma_sync_single_range_for_cpu(aq_nic_get_dev(self->aq_nic),
					      buff->rxdata.daddr,
					      buff->rxdata.pg_off,
					      buff->len, DMA_FROM_DEVICE);

		skb = napi_alloc_skb(napi, AQ_CFG_RX_HDR_SIZE);
		if (unlikely(!skb)) {
			err = -ENOMEM;
			goto err_exit;
		}

		hdr_len = min_t(u16, buff->len, AQ_CFG_RX_HDR_SIZE);
		skb_put(skb, hdr_len);
		memcpy(skb->data, aq_buf_vaddr(&buff->rxdata), hdr_len);

		if (buff->len - hdr_len > 0) {
			skb_add_rx_frag(skb, 0, buff->rxdata.page,
					buff->rxdata.pg_off + hdr_len,
					buff->len - hdr_len,
					AQ_CFG_RX_FRAME_MAX);
			page_ref_inc(buff->rxdata.page);
		}

		if (!buff->is_eop) {
			for (i = 1U, next_ = buff->next,
			     buff_ = &self->buff_ring[next_]; true;
			     next_ = buff_->next,
			     buff_ = &self->buff_ring[next_], ++i) {
				dma_sync_single_range_for_cpu(
						aq_nic_get_dev(self->aq_nic),
						buff_->rxdata.daddr,
						buff_->rxdata.pg_off,
						buff_->len, DMA_FROM_DEVICE);
				skb_add_rx_frag(skb, i,
						buff_->rxdata.page,
						buff_->rxdata.pg_off,
						buff_->len,
						AQ_CFG_RX_FRAME_MAX);
				page_ref_inc(buff_->rxdata.page);
				buff_->is_cleaned = 1;

				if (buff_->is_eop)
					break;
			}
		}

		skb->protocol = eth_type_trans(skb, ndev);

		if (unlikely(buff->is_cso_err)) {
			++self->stats.rx.errors;
			skb->ip_summed = CHECKSUM_NONE;
		} else {
			if (buff->is_ip_cso) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
				__skb_incr_checksum_unnecessary(skb);
				if (buff->is_udp_cso || buff->is_tcp_cso)
					__skb_incr_checksum_unnecessary(skb);
#else
				skb->ip_summed = CHECKSUM_UNNECESSARY;
#endif
			} else {
				skb->ip_summed = CHECKSUM_NONE;
			}
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0) || (RHEL_RELEASE_CODE > 0)
		skb_set_hash(skb, buff->rss_hash,
			     buff->is_hash_l4 ? PKT_HASH_TYPE_L4 :
			     PKT_HASH_TYPE_NONE);
#else
		skb->rxhash = buff->rss_hash;
#endif

		skb_record_rx_queue(skb, self->idx);

		++self->stats.rx.packets;
		self->stats.rx.bytes += skb->len;

		napi_gro_receive(napi, skb);

	}

err_exit:
	return err;
}

int aq_ring_rx_fill(struct aq_ring_s *self)
{
	unsigned int page_order = self->page_order;
	struct aq_ring_buff_s *buff = NULL;
	int err = 0;
	int i = 0;

	if (aq_ring_avail_dx(self) < min_t(unsigned, aq_rx_refill_thres, self->size/2))
		return err;

	for (i = aq_ring_avail_dx(self); i--;
		self->sw_tail = aq_ring_next_dx(self, self->sw_tail)) {
		buff = &self->buff_ring[self->sw_tail];

		buff->flags = 0U;
		buff->len = AQ_CFG_RX_FRAME_MAX;

		err = aq_get_rxpages(self, buff, page_order);
		if (err)
			goto err_exit;

		buff->pa = aq_buf_daddr(&buff->rxdata);
		buff = NULL;
	}

err_exit:
	return err;
}

void aq_ring_rx_deinit(struct aq_ring_s *self)
{
	if (!self)
		goto err_exit;

	for (; self->sw_head != self->sw_tail;
		self->sw_head = aq_ring_next_dx(self, self->sw_head)) {
		struct aq_ring_buff_s *buff = &self->buff_ring[self->sw_head];

		aq_free_rxpage(&buff->rxdata, aq_nic_get_dev(self->aq_nic));

	}

err_exit:;
}

void aq_ring_free(struct aq_ring_s *self)
{
	if (!self)
		goto err_exit;

	kfree(self->buff_ring);

	if (self->dx_ring)
		dma_free_coherent(aq_nic_get_dev(self->aq_nic),
				  self->size * self->dx_size, self->dx_ring,
				  self->dx_ring_pa);

err_exit:;
}
