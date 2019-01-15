/*
 * Aquantia Corporation Network Driver
 * Copyright (C) 2014-2016 Aquantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * File aq_ptp.c:
 * Definition of functions for Linux PTP support.
 */

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>

#include "aq_nic.h"
#include "aq_hw.h"
#include "aq_ptp.h"
#include "aq_ring.h"
#include "aq_nic.h"
#include "aq_hw_utils.h"
#include "aq_main.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))

#define AQ_PTP_TX_TIMEOUT        (HZ *  10)

static unsigned int aq_ptp_offset_forced = 0;
module_param(aq_ptp_offset_forced, uint, 0644);
MODULE_PARM_DESC(aq_ptp_offset_forced, "Force to use the driver parameters");

static unsigned int aq_ptp_offset_100 = 0;
module_param(aq_ptp_offset_100, uint, 0644);
MODULE_PARM_DESC(aq_ptp_offset_100, "PTP offset for 100M");

static unsigned int aq_ptp_offset_1000 = 0;
module_param(aq_ptp_offset_1000, uint, 0644);
MODULE_PARM_DESC(aq_ptp_offset_1000, "PTP offset for 1G");

static unsigned int aq_ptp_offset_2500 = 0;
module_param(aq_ptp_offset_2500, uint, 0644);
MODULE_PARM_DESC(aq_ptp_offset_2500, "PTP offset for 2,5G");

static unsigned int aq_ptp_offset_5000 = 0;
module_param(aq_ptp_offset_5000, uint, 0644);
MODULE_PARM_DESC(aq_ptp_offset_5000, "PTP offset for 5G");

static unsigned int aq_ptp_offset_10000 = 0;
module_param(aq_ptp_offset_10000, uint, 0644);
MODULE_PARM_DESC(aq_ptp_offset_10000, "PTP offset for 10G");

enum ptp_speed_offsets {
	ptp_offset_idx_10 = 0,
	ptp_offset_idx_100,
	ptp_offset_idx_1000,
	ptp_offset_idx_2500,
	ptp_offset_idx_5000,
	ptp_offset_idx_10000,
};

struct ptp_skb_ring {
	struct sk_buff **buff;
	spinlock_t lock;
	unsigned int size;
	volatile unsigned int head;
	volatile unsigned int tail;
};

struct ptp_tx_timeout {
	spinlock_t lock;
	bool active;
	unsigned long tx_start;
};

struct aq_ptp_s {
	struct aq_nic_s *aq_nic;

	struct hwtstamp_config hwtstamp_config;

	spinlock_t ptp_lock;
	spinlock_t ptp_ring_lock;
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_info;

	atomic_t offset_egress;
	atomic_t offset_ingress;

	struct aq_ring_param_s ptp_ring_param;

	struct ptp_tx_timeout ptp_tx_timeout;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	unsigned int num_vector;
#endif
	unsigned int idx_vector;
	struct napi_struct napi;

	struct aq_ring_s ptp_tx;
	struct aq_ring_s ptp_rx;
	struct aq_ring_s hwts_rx;

	struct ptp_skb_ring skb_ring;
};

struct ptp_tm_offset {
	unsigned int mbps;
	int egress;
	int ingress;
};

static struct ptp_tm_offset ptp_offset[6];

static inline int aq_ptp_tm_offset_egress_get(struct aq_ptp_s *self)
{
  return atomic_read(&self->offset_egress);
}

static inline int aq_ptp_tm_offset_ingress_get(struct aq_ptp_s *self)
{
  return atomic_read(&self->offset_ingress);
}

void aq_ptp_tm_offset_set(struct aq_nic_s *aq_nic, unsigned int mbps)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	int i, egress, ingress;

	if (!self)
		return;

	egress = ingress = 0;

	for (i = 0; i < ARRAY_SIZE(ptp_offset); i++) {
		if (mbps == ptp_offset[i].mbps) {
			egress = ptp_offset[i].egress;
			ingress = ptp_offset[i].ingress;
			break;
		}
	}

	atomic_set(&self->offset_egress, egress);
	atomic_set(&self->offset_ingress, ingress);
}

static int __aq_ptp_skb_put(struct ptp_skb_ring *ring, struct sk_buff *skb)
{
	unsigned int next_head = (ring->head + 1) % ring->size;

	if (next_head == ring->tail)
		return -1;

	ring->buff[ring->head] = skb_get(skb);
	ring->head = next_head;

	return 0;
}

static int aq_ptp_skb_put(struct ptp_skb_ring *ring, struct sk_buff *skb)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&ring->lock, flags);
	ret = __aq_ptp_skb_put(ring, skb);
	spin_unlock_irqrestore(&ring->lock, flags);

	return ret;
}

static struct sk_buff *__aq_ptp_skb_get(struct ptp_skb_ring *ring)
{
	struct sk_buff *skb;

	if (ring->tail == ring->head)
		return NULL;

	skb = ring->buff[ring->tail];
	ring->tail = (ring->tail + 1) % ring->size;

	return skb;
}

static struct sk_buff *aq_ptp_skb_get(struct ptp_skb_ring *ring)
{
	unsigned long flags;
	struct sk_buff *skb;

	spin_lock_irqsave(&ring->lock, flags);
	skb = __aq_ptp_skb_get(ring);
	spin_unlock_irqrestore(&ring->lock, flags);

	return skb;
}

static unsigned int aq_ptp_skb_buf_len(struct ptp_skb_ring *ring)
{
  unsigned long flags;
  unsigned int len;

  spin_lock_irqsave(&ring->lock, flags);
  len = (ring->head >= ring->tail) ?
    ring->head - ring->tail :
    ring->size - ring->tail + ring->head;
  spin_unlock_irqrestore(&ring->lock, flags);

  return len;
}

static int aq_ptp_skb_ring_init(struct ptp_skb_ring *ring, unsigned int size)
{
	struct sk_buff **buff = kmalloc(sizeof(*buff) * size, GFP_KERNEL);
	if (!buff) {
		return -ENOMEM;
	}

	spin_lock_init(&ring->lock);

	ring->buff = buff;
	ring->size = size;
	ring->head = ring->tail = 0;

	return 0;
}

static void aq_ptp_skb_ring_clean(struct ptp_skb_ring *ring)
{
	struct sk_buff *skb;
	while ((skb = aq_ptp_skb_get(ring)) != NULL)
		dev_kfree_skb_any(skb);
}

static void aq_ptp_skb_ring_release(struct ptp_skb_ring *ring)
{
	if (ring->buff) {
		aq_ptp_skb_ring_clean(ring);
		kfree(ring->buff);
		ring->buff = NULL;
	}
}

static void aq_ptp_tx_timeout_init(struct ptp_tx_timeout *timeout)
{
	spin_lock_init(&timeout->lock);
	timeout->active = false;
}

static void aq_ptp_tx_timeout_start(struct aq_ptp_s *self)
{
	struct ptp_tx_timeout *timeout = &self->ptp_tx_timeout;
	unsigned long flags;

	spin_lock_irqsave(&timeout->lock, flags);
	timeout->active = true;
	timeout->tx_start = jiffies;
	spin_unlock_irqrestore(&timeout->lock, flags);
}

static void aq_ptp_tx_timeout_update(struct aq_ptp_s *self)
{
	if (!aq_ptp_skb_buf_len(&self->skb_ring)) {
		struct ptp_tx_timeout *timeout = &self->ptp_tx_timeout;
		unsigned long flags;

		spin_lock_irqsave(&timeout->lock, flags);
		timeout->active = false;
		spin_unlock_irqrestore(&timeout->lock, flags);
	}
}

static void aq_ptp_tx_timeout_check(struct aq_ptp_s *self)
{
	struct ptp_tx_timeout *timeout = &self->ptp_tx_timeout;
	unsigned long flags;
	bool timeout_flag;

	timeout_flag = false;

	spin_lock_irqsave(&timeout->lock, flags);
	if (timeout->active) {
		timeout_flag = time_is_before_jiffies(timeout->tx_start + AQ_PTP_TX_TIMEOUT);
		/* reset active flag if timeout detected */
		if (timeout_flag)
			timeout->active = false;
	}
	spin_unlock_irqrestore(&timeout->lock, flags);

	if (timeout_flag) {
		aq_ptp_skb_ring_clean(&self->skb_ring);
		aq_nic_print(self->aq_nic, err, drv, "PTP Timeout. Clearing Tx Timestamp SKBs\n");
	}
}

/*
 * aq_ptp_adjfreq
 * @ptp: the ptp clock structure
 * @ppb: parts per billion adjustment from base
 *
 * adjust the frequency of the ptp cycle counter by the
 * indicated ppb from the base frequency.
 */
static int aq_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	struct aq_ptp_s *self = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = self->aq_nic;

	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_hw_ops->hw_adj_clock_freq(aq_nic->aq_hw, ppb);
	mutex_unlock(&aq_nic->fwreq_mutex);

	return 0;
}

/*
 * aq_ptp_adjtime
 * @ptp: the ptp clock structure
 * @delta: offset to adjust the cycle counter by
 *
 * adjust the timer by resetting the timecounter structure.
 */
static int aq_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct aq_ptp_s *self = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = self->aq_nic;
	unsigned long flags;

	spin_lock_irqsave(&self->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_adj_sys_clock(aq_nic->aq_hw, delta);
	spin_unlock_irqrestore(&self->ptp_lock, flags);

	return 0;
}

/*
 * aq_ptp_gettime
 * @ptp: the ptp clock structure
 * @ts: timespec structure to hold the current time value
 *
 * read the timecounter and return the correct value on ns,
 * after converting it into a struct timespec.
 */
static int aq_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct aq_ptp_s *self = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = self->aq_nic;
	unsigned long flags;
	u64 ns;

	spin_lock_irqsave(&self->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &ns);
	spin_unlock_irqrestore(&self->ptp_lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

/*
 * aq_ptp_settime
 * @ptp: the ptp clock structure
 * @ts: the timespec containing the new time for the cycle counter
 *
 * reset the timecounter to use a new base value instead of the kernel
 * wall timer value.
 */
static int aq_ptp_settime(struct ptp_clock_info *ptp,
				 const struct timespec64 *ts)
{
	struct aq_ptp_s *self = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = self->aq_nic;
	unsigned long flags;
	u64 ns = timespec64_to_ns(ts);
	u64 now;

	spin_lock_irqsave(&self->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &now);
	aq_nic->aq_hw_ops->hw_adj_sys_clock(aq_nic->aq_hw, (s64)ns - (s64)now);

	spin_unlock_irqrestore(&self->ptp_lock, flags);

	return 0;
}

static void aq_ptp_convert_to_hwtstamp(struct aq_ptp_s *self,
				       struct skb_shared_hwtstamps *hwtstamp,
				       u64 timestamp)
{
	memset(hwtstamp, 0, sizeof(*hwtstamp));
	hwtstamp->hwtstamp = ns_to_ktime(timestamp);
}

/*
 * aq_ptp_gpio_feature_enable
 * @ptp: the ptp clock structure
 * @rq: the requested feature to change
 * @on: whether to enable or disable the feature
 */
static int aq_ptp_gpio_feature_enable(struct ptp_clock_info *ptp,
					struct ptp_clock_request *rq, int on)
{
	struct aq_ptp_s *self = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = self->aq_nic;
	u64 start, period;
	u32 pin_index;

	/* we can only support periodic output */
	if (rq->type != PTP_CLK_REQ_PEROUT && rq->type != PTP_CLK_REQ_PPS)
		return -ENOTSUPP;

	/* We cannot enforce start time as there is no
	 * mechanism for that in the hardware, we can only control
	 * the period.
	 */

	if (rq->type == PTP_CLK_REQ_PEROUT) {
		struct ptp_clock_time *s = &rq->perout.start;
		struct ptp_clock_time *t = &rq->perout.period;

		pin_index = rq->perout.index;

		/* we cannot support periods greater
		 * than 4 seconds due to reg limit
		 */
		if (t->sec > 4 || t->sec < 0)
			return -ERANGE;

		/* convert to unsigned 64b ns,
		 * verify we can put it in a 32b register
		 */
		period = on ? t->sec * 1000000000LL + t->nsec : 0;

		/* verify the value is in range supported by hardware */
		if (period > U32_MAX)
			return -ERANGE;
		/* convert to unsigned 64b ns */
		/* TODO convert to AQ time */
		start = on ? s->sec * 1000000000LL + s->nsec : 0;
	} else {
		u64 rest = 0;

		pin_index = 0;

		aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &start);
		rest = start % 1000000000LL;
		period = on ? 1000000000LL : 0; /* PPS - pulse per second */
		start = on ? start - rest + 1000000000LL *
			     (rest > 990000000LL ? 2 : 1) : 0;
	}

	/* verify the request channel is there */
	if (pin_index >= ptp->n_per_out)
		return -EINVAL;

	if (on)
		aq_nic_print(aq_nic, info, drv, "Enable GPIO %d pulsing, "
			     "start time %llu, period %u\n", pin_index,
			     start, (u32)period);
	else
		aq_nic_print(aq_nic, info, drv, "Disable GPIO %d pulsing, "
			     "start time %llu, period %u\n", pin_index,
			     start, (u32)period);


	/* Notify hardware of request to being sending pulses.
	 * If period is ZERO then pulsen is disabled.
	 */
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_hw_ops->hw_gpio_pulse(aq_nic->aq_hw, pin_index,
					 start, (u32)period);
	mutex_unlock(&aq_nic->fwreq_mutex);

	return 0;
}

/*
 * aq_ptp_verify
 * @ptp: the ptp clock structure
 * @pin: index of the pin in question
 * @func: the desired function to use
 * @chan: the function channel index to use
 */
 static int aq_ptp_verify(struct ptp_clock_info *ptp, unsigned int pin,
			  enum ptp_pin_function func, unsigned int chan)
{
	/* verify the requested pin is there */
	if (!ptp->pin_config || pin >= ptp->n_pins)
		return -EINVAL;

	/* enforce locked channels, no changing them */
	if (chan != ptp->pin_config[pin].chan)
		return -EINVAL;

	/* we want to keep the functions locked as well */
	if (func != ptp->pin_config[pin].func)
		return -EINVAL;

	return 0;
}

/*
 * aq_ptp_tx_hwtstamp - utility function which checks for TX time stamp
 * @adapter: the private adapter struct
 *
 * if the timestamp is valid, we convert it into the timecounter ns
 * value, then store that result into the shhwtstamps structure which
 * is passed up the network stack
 */
void aq_ptp_tx_hwtstamp(struct aq_nic_s *aq_nic, u64 timestamp)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	struct sk_buff *skb = aq_ptp_skb_get(&self->skb_ring);
	struct skb_shared_hwtstamps hwtstamp;

	if (!skb) {
		aq_nic_print(aq_nic, err, drv, "have timestamp but tx_queus empty\n");
		return;
	}

	timestamp += aq_ptp_tm_offset_egress_get(self);
	aq_ptp_convert_to_hwtstamp(self, &hwtstamp, timestamp);
	skb_tstamp_tx(skb, &hwtstamp);
	dev_kfree_skb_any(skb);

	aq_ptp_tx_timeout_update(self);
}

/*
 * aq_ptp_rx_hwtstamp - utility function which checks for RX time stamp
 * @adapter: pointer to adapter struct
 * @skb: particular skb to send timestamp with
 *
 * if the timestamp is valid, we convert it into the timecounter ns
 * value, then store that result into the shhwtstamps structure which
 * is passed up the network stack
 */
static void aq_ptp_rx_hwtstamp(struct aq_ptp_s *self, struct sk_buff *skb,
			       u64 timestamp)
{
	timestamp -= aq_ptp_tm_offset_ingress_get(self);
	aq_ptp_convert_to_hwtstamp(self, skb_hwtstamps(skb), timestamp);
}

void aq_ptp_hwtstamp_config_get(struct aq_ptp_s *self,
				struct hwtstamp_config *config)
{
	*config = self->hwtstamp_config;
}

int aq_ptp_hwtstamp_config_set(struct aq_ptp_s *self,
			       struct hwtstamp_config *config)
{
	struct aq_nic_s *aq_nic = self->aq_nic;
	int err;

	if ((config->tx_type == HWTSTAMP_TX_ON) ||
			(config->rx_filter == HWTSTAMP_FILTER_PTP_V2_EVENT)) {
		err = aq_nic->aq_hw_ops->hw_ptp_dpath_enable(aq_nic->aq_hw, 1,
							     self->ptp_rx.idx);
		aq_utils_obj_set(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP);
	} else {
		err = aq_nic->aq_hw_ops->hw_ptp_dpath_enable(aq_nic->aq_hw, 0,
							     self->ptp_rx.idx);
		aq_utils_obj_clear(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP);
	}

	if (err)
		return -EREMOTEIO;

	self->hwtstamp_config = *config;

	return 0;
}

static u16 aq_ptp_pdata_rx_hook(struct aq_nic_s *aq_nic,
				struct sk_buff *skb, u8 *p,
				unsigned int len)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	u64 timestamp = 0;
	u16 ret = aq_nic->aq_hw_ops->rx_extract_ts(p, len, &timestamp);

	if (ret > 0)
		aq_ptp_rx_hwtstamp(self, skb, timestamp);

	return ret;
}

static int aq_ptp_poll(struct napi_struct *napi, int budget)
{
	struct aq_ptp_s *self = container_of(napi, struct aq_ptp_s, napi);
	struct aq_nic_s *aq_nic = self->aq_nic;
	bool was_cleaned = false;
	int work_done = 0;
	int err;

	/* Processing PTP TX traffic */
	err = aq_nic->aq_hw_ops->hw_ring_tx_head_update(aq_nic->aq_hw,
							&self->ptp_tx);
	if (err < 0)
		goto err_exit;

	if (self->ptp_tx.sw_head != self->ptp_tx.hw_head) {
		aq_ring_tx_clean(&self->ptp_tx);

		was_cleaned = true;
	}

	/* Processing HW_TIMESTAMP RX traffic */
	err = aq_nic->aq_hw_ops->hw_ring_hwts_rx_receive(aq_nic->aq_hw,
							 &self->hwts_rx);
	if (err < 0)
		goto err_exit;

	if (self->hwts_rx.sw_head != self->hwts_rx.hw_head) {
		aq_ring_hwts_rx_clean(&self->hwts_rx, aq_nic);

		err = aq_nic->aq_hw_ops->hw_ring_hwts_rx_fill(aq_nic->aq_hw,
							      &self->hwts_rx);

		was_cleaned = true;
	}

	/* Processing PTP RX traffic */
	err = aq_nic->aq_hw_ops->hw_ring_rx_receive(aq_nic->aq_hw, &self->ptp_rx);
	if (err < 0)
		goto err_exit;

	if (self->ptp_rx.sw_head != self->ptp_rx.hw_head) {
		unsigned int sw_tail_old;
		err = aq_ring_rx_clean(&self->ptp_rx, napi, &work_done,
				       budget, aq_ptp_pdata_rx_hook);
		if (err < 0)
			goto err_exit;

		sw_tail_old = self->ptp_rx.sw_tail;
		err = aq_ring_rx_fill(&self->ptp_rx);
		if (err < 0)
			goto err_exit;

		err = aq_nic->aq_hw_ops->hw_ring_rx_fill(aq_nic->aq_hw,
							 &self->ptp_rx,
							 sw_tail_old);
		if (err < 0)
			goto err_exit;
	}

	if (was_cleaned)
		work_done = budget;

	if (work_done < budget) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
		napi_complete_done(napi, work_done);
#else
		napi_complete(napi);
#endif
		aq_nic->aq_hw_ops->hw_irq_enable(aq_nic->aq_hw,
						 1 << self->ptp_ring_param.vec_idx);
	}

err_exit:
	return work_done;
}

static irqreturn_t aq_ptp_isr(int irq, void *private)
{
	struct aq_ptp_s *self = private;
	int err = 0;

	if (!self) {
		err = -EINVAL;
		goto err_exit;
	}
	napi_schedule(&self->napi);

err_exit:
	return err >= 0 ? IRQ_HANDLED : IRQ_NONE;
}

int aq_ptp_xmit(struct aq_nic_s *aq_nic, struct sk_buff *skb)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	struct aq_ring_s *ring = &self->ptp_tx;
	unsigned long irq_flags;
	int err = NETDEV_TX_OK;
	unsigned int frags;

	if (skb->len <= 0) {
		dev_kfree_skb_any(skb);
		goto err_exit;
	}

	frags = skb_shinfo(skb)->nr_frags + 1;
	/* Frags cannot be bigger 16KB
	 * because PTP usually works
	 * without Jumbo even in a background
	 */
	if (frags > AQ_CFG_SKB_FRAGS_MAX || frags > aq_ring_avail_dx(ring)) {
		/* Drop packet because it doesn't make sence to delay it */
		dev_kfree_skb_any(skb);
		goto err_exit;
	}


	err = aq_ptp_skb_put(&self->skb_ring, skb);
	if (err) {
		aq_nic_print(aq_nic, err, drv, "SKB Ring is overflow (%u)!\n",
			     ring->size);
		return NETDEV_TX_BUSY;
	}
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	aq_ptp_tx_timeout_start(self);
	skb_tx_timestamp(skb);

	spin_lock_irqsave(&aq_nic->aq_ptp->ptp_ring_lock, irq_flags);
	frags = aq_nic_map_skb(aq_nic, skb, ring);

	if (likely(frags)) {
		err = aq_nic->aq_hw_ops->hw_ring_tx_xmit(aq_nic->aq_hw,
						       ring, frags);
		if (err >= 0) {
			++ring->stats.tx.packets;
			ring->stats.tx.bytes += skb->len;
		}
	} else {
		err = NETDEV_TX_BUSY;
	}
	spin_unlock_irqrestore(&aq_nic->aq_ptp->ptp_ring_lock, irq_flags);

err_exit:
	return err;
}

void aq_ptp_service_task(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;

	if (!self)
		return;

	aq_ptp_tx_timeout_check(self);
}

int aq_ptp_irq_alloc(struct aq_nic_s *aq_nic)
{
	struct pci_dev *pdev = aq_nic->pdev;
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	int err = 0;

	if (!self)
		return 0;

	if (pdev->msix_enabled || pdev->msi_enabled) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
		err = request_irq(self->num_vector, aq_ptp_isr, 0,
				aq_nic->ndev->name, self);
#else
		err = request_irq(pci_irq_vector(pdev, self->idx_vector),
				  aq_ptp_isr, 0, aq_nic->ndev->name, self);
#endif
	} else {
		err = -EINVAL;
		goto err_exit;
	}

err_exit:
	return err;
}

void aq_ptp_irq_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	struct pci_dev *pdev = aq_nic->pdev;
#endif

	if (!self)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	free_irq(pci_irq_vector(pdev, self->idx_vector), self);
#else
	free_irq(self->num_vector, self);
#endif
}

int aq_ptp_ring_init(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	int err = 0;

	if (!self)
		return 0;

	err = aq_ring_init(&self->ptp_tx);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_tx_init(aq_nic->aq_hw,
						 &self->ptp_tx,
						 &self->ptp_ring_param);
	if (err < 0)
		goto err_exit;
	if (aq_nic->aq_hw_ops->hw_tx_ptp_ring_init) {
		err = aq_nic->aq_hw_ops->hw_tx_ptp_ring_init(aq_nic->aq_hw,
							     &self->ptp_tx);
		if (err < 0)
			goto err_exit;
	}

	err = aq_ring_init(&self->ptp_rx);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_rx_init(aq_nic->aq_hw,
						 &self->ptp_rx,
						 &self->ptp_ring_param);
	if (err < 0)
		goto err_exit;
	if (aq_nic->aq_hw_ops->hw_rx_ptp_ring_init) {
		err = aq_nic->aq_hw_ops->hw_rx_ptp_ring_init(aq_nic->aq_hw,
							     &self->ptp_rx);
		if (err < 0)
			goto err_exit;
	}

	err = aq_ring_rx_fill(&self->ptp_rx);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_rx_fill(aq_nic->aq_hw,
						 &self->ptp_rx,
						 0U);
	if (err < 0)
		goto err_exit;

	err = aq_ring_init(&self->hwts_rx);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_rx_init(aq_nic->aq_hw,
						 &self->hwts_rx,
						 &self->ptp_ring_param);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_hwts_rx_fill(aq_nic->aq_hw,
						      &self->hwts_rx);
	if (err < 0)
		goto err_exit;

err_exit:
	return err;
}

int aq_ptp_ring_start(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	int err = 0;

	if (!self)
		return 0;

	err = aq_nic->aq_hw_ops->hw_ring_tx_start(aq_nic->aq_hw, &self->ptp_tx);
	if (err < 0)
		goto err_exit;

	err = aq_nic->aq_hw_ops->hw_ring_rx_start(aq_nic->aq_hw, &self->ptp_rx);
	if (err < 0)
		goto err_exit;

	err = aq_nic->aq_hw_ops->hw_ring_rx_start(aq_nic->aq_hw, &self->hwts_rx);
	if (err < 0)
		goto err_exit;

	napi_enable(&self->napi);

err_exit:
	return err;
}

void aq_ptp_ring_stop(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;

	if (!self)
		return;

	aq_nic->aq_hw_ops->hw_ring_tx_stop(aq_nic->aq_hw, &self->ptp_tx);
	aq_nic->aq_hw_ops->hw_ring_rx_stop(aq_nic->aq_hw, &self->ptp_rx);

	aq_nic->aq_hw_ops->hw_ring_rx_stop(aq_nic->aq_hw, &self->hwts_rx);

	napi_disable(&self->napi);
}

void aq_ptp_ring_deinit(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;

	if (!self || !self->ptp_tx.aq_nic || !self->ptp_rx.aq_nic)
		return;

	aq_ring_tx_clean(&self->ptp_tx);
	aq_ring_rx_deinit(&self->ptp_rx);
}

#define PTP_8TC_RING_IDX             8
#define PTP_4TC_RING_IDX            16
#define PTP_HWST_RING_IDX           31

int aq_ptp_ring_alloc(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	unsigned int tx_ring_idx, rx_ring_idx;
	struct aq_ring_s *hwts = 0;
	u32 tx_tc_mode, rx_tc_mode;
	struct aq_ring_s *ring;
	int err;

	if (!self)
		return 0;

	/* Index must to be 8 (8 TCs) or 16 (4 TCs).
	 * It depends from Traffic Class mode.
	 */
	aq_nic->aq_hw_ops->hw_tx_tc_mode_get(aq_nic->aq_hw, &tx_tc_mode);
	if (tx_tc_mode == 0)
		tx_ring_idx = PTP_8TC_RING_IDX;
	else
		tx_ring_idx = PTP_4TC_RING_IDX;

	ring = aq_ring_tx_alloc(&self->ptp_tx, aq_nic,
			tx_ring_idx, &aq_nic->aq_nic_cfg);
	if (!ring) {
		err = -ENOMEM;
		goto err_exit_1;
	}

	aq_nic->aq_hw_ops->hw_rx_tc_mode_get(aq_nic->aq_hw, &rx_tc_mode);
	if (rx_tc_mode == 0)
		rx_ring_idx = PTP_8TC_RING_IDX;
	else
		rx_ring_idx = PTP_4TC_RING_IDX;

	ring = aq_ring_rx_alloc(&self->ptp_rx, aq_nic,
			rx_ring_idx, &aq_nic->aq_nic_cfg);
	if (!ring) {
		err = -ENOMEM;
		goto err_exit_2;
	}

	hwts = aq_ring_hwts_rx_alloc(&self->hwts_rx, aq_nic, PTP_HWST_RING_IDX,
				     aq_nic->aq_nic_cfg.rxds,
				     aq_nic->aq_nic_cfg.aq_hw_caps->rxd_size);
	if (!hwts) {
		err = -ENOMEM;
		goto err_exit_3;
	}

	err = aq_ptp_skb_ring_init(&self->skb_ring, aq_nic->aq_nic_cfg.rxds);
	if (err != 0) {
		err = -ENOMEM;
		goto err_exit_4;
	}

	self->ptp_ring_param.vec_idx = self->idx_vector;
	self->ptp_ring_param.cpu = self->ptp_ring_param.vec_idx +
			aq_nic_get_cfg(aq_nic)->aq_rss.base_cpu_number;
	cpumask_set_cpu(self->ptp_ring_param.cpu,
			&self->ptp_ring_param.affinity_mask);

	return 0;

err_exit_4:
	aq_ring_free(&self->hwts_rx);
err_exit_3:
	aq_ring_free(&self->ptp_rx);
err_exit_2:
	aq_ring_free(&self->ptp_tx);
err_exit_1:
	return err;
}

void aq_ptp_ring_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;

	if (!self)
		return;

	aq_ring_free(&self->ptp_tx);
	aq_ring_free(&self->ptp_rx);
	aq_ring_free(&self->hwts_rx);

	aq_ptp_skb_ring_release(&self->skb_ring);
}

#define MAX_PTP_GPIO_COUNT 3
static struct ptp_pin_desc aq_ptp_pd[MAX_PTP_GPIO_COUNT] = {
	{
		.name = "AQ_GPIO0",
		.index = 0,
		.func = PTP_PF_PEROUT,
		.chan = 0
	},
	{
		.name = "AQ_GPIO1",
		.index = 1,
		.func = PTP_PF_PEROUT,
		.chan = 1
	},
	{
		.name = "AQ_GPIO2",
		.index = 2,
		.func = PTP_PF_PEROUT,
		.chan = 2
	}
};

static struct ptp_clock_info aq_ptp_clock = {
	.owner		= THIS_MODULE,
	.name		= "atlantic ptp",
	.max_adj	= 999999999,
	.n_ext_ts	= 0,
	.pps		= 0,
	.adjfreq	= aq_ptp_adjfreq,
	.adjtime	= aq_ptp_adjtime,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	.gettime64	= aq_ptp_gettime,
	.settime64	= aq_ptp_settime,
#else
	.gettime	= aq_ptp_gettime,
	.settime	= aq_ptp_settime,
#endif
	/* enable periodic outputs */
	.n_per_out     = 1,
	.enable        = aq_ptp_gpio_feature_enable,
	/* enable clock pins */
	.n_pins        = 1,
	.verify        = aq_ptp_verify,
	.pin_config    = aq_ptp_pd,
};

#define ptp_offset_init(__idx, __mbps, __egress, __ingress)   do { \
		ptp_offset[__idx].mbps = (__mbps); \
		ptp_offset[__idx].egress = (__egress); \
		ptp_offset[__idx].ingress = (__ingress); } while(0)

static void aq_ptp_offset_init_from_fw(const struct hw_aq_ptp_offset *offsets)
{
	int i;

	/* Load offsets for PTP */
	for (i = 0; i < ARRAY_SIZE(ptp_offset); i++) {
		switch (i) {
			/* 100M */
			case ptp_offset_idx_100:
				ptp_offset_init(i, 100,
						offsets->egress_100,
						offsets->ingress_100);
				break;
			/* 1G */
			case ptp_offset_idx_1000:
				ptp_offset_init(i, 1000,
						offsets->egress_1000,
						offsets->ingress_1000);
				break;
			/* 2.5G */
			case ptp_offset_idx_2500:
				ptp_offset_init(i, 2500,
						offsets->egress_2500,
						offsets->ingress_2500);
				break;
			/* 5G */
			case ptp_offset_idx_5000:
				ptp_offset_init(i, 5000,
						offsets->egress_5000,
						offsets->ingress_5000);
				break;
			/* 10G */
			case ptp_offset_idx_10000:
				ptp_offset_init(i, 10000,
						offsets->egress_10000,
						offsets->ingress_10000);
				break;
		}
	}
}

static void aq_ptp_offset_init_from_params(int force)
{
	if (force || aq_ptp_offset_100)
		ptp_offset_init(ptp_offset_idx_100, 100,
				(aq_ptp_offset_100 >> 16) & 0xffff,
				aq_ptp_offset_100 & 0xffff);
	if (force || aq_ptp_offset_1000)
		ptp_offset_init(ptp_offset_idx_1000, 1000,
				(aq_ptp_offset_1000 >> 16) & 0xffff,
				aq_ptp_offset_1000 & 0xffff);
	if (force || aq_ptp_offset_2500)
		ptp_offset_init(ptp_offset_idx_2500, 2500,
				(aq_ptp_offset_2500 >> 16) & 0xffff,
				aq_ptp_offset_2500 & 0xffff);
	if (force || aq_ptp_offset_5000)
		ptp_offset_init(ptp_offset_idx_5000, 5000,
				(aq_ptp_offset_5000 >> 16) & 0xffff,
				aq_ptp_offset_5000 & 0xffff);
	if (force || aq_ptp_offset_10000)
		ptp_offset_init(ptp_offset_idx_10000, 10000,
				(aq_ptp_offset_10000 >> 16) & 0xffff,
				aq_ptp_offset_10000 & 0xffff);
}

static void aq_ptp_offset_init(const struct hw_aq_ptp_offset *offsets)
{
	memset(ptp_offset, 0, sizeof(ptp_offset));

	if (aq_ptp_offset_forced) {
		aq_ptp_offset_init_from_params(1);
	} else {
		aq_ptp_offset_init_from_fw(offsets);
		aq_ptp_offset_init_from_params(0);
	}
}

static void aq_ptp_gpio_init(enum gpio_pin_function gpio_pin[3])
{
	u32 ncount = 0;
	u32 i;

	for (i = 0; i < MAX_PTP_GPIO_COUNT; i++) {
		if (gpio_pin[i] == (GPIO_PIN_FUNCTION_PTP0 + ncount)) {
			/* .name = "AQ_GPIO2",
			 * .index = 2,
			 * .func = PTP_PF_PEROUT,
			 * .chan = 2
			 */
			aq_ptp_clock.pin_config[ncount].name[7] = '0' + i;
			aq_ptp_clock.pin_config[ncount].index = i;
			aq_ptp_clock.pin_config[ncount++].chan = i;
		}
	}
	aq_ptp_clock.n_pins = ncount;
	aq_ptp_clock.n_per_out = ncount;
}

void aq_ptp_clock_init(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	aq_ptp_settime(&self->ptp_info, &ts);

}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
int aq_ptp_init(struct aq_nic_s *aq_nic, unsigned int idx_vec, unsigned int num_vec)
#else
int aq_ptp_init(struct aq_nic_s *aq_nic, unsigned int idx_vec)
#endif
{
	struct hw_aq_atl_utils_mbox mbox;
	struct ptp_clock *clock;
	struct aq_ptp_s *self;
	int err = 0;

	if (!aq_nic->aq_hw_ops->hw_get_ptp_ts) {
		aq_nic->aq_ptp = NULL;
		return 0;
	}

	if (!aq_nic->aq_fw_ops->enable_ptp) {
		aq_nic->aq_ptp = NULL;
		return 0;
	}

	hw_atl_utils_mpi_read_stats(aq_nic->aq_hw, &mbox);
	if (!(mbox.info.caps_ex & BIT(CAPS_EX_PHY_PTP_EN))) {
		aq_nic->aq_ptp = NULL;
		return 0;
	}

	aq_ptp_offset_init(&mbox.info.ptp_offset);

	self = kzalloc(sizeof(*self), GFP_KERNEL);
	if (!self) {
		err = -ENOMEM;
		goto err_exit;
	}

	self->aq_nic = aq_nic;
	aq_ptp_gpio_init(mbox.info.gpio_pin);

	spin_lock_init(&self->ptp_lock);
	spin_lock_init(&self->ptp_ring_lock);

	self->ptp_info = aq_ptp_clock;
	clock = ptp_clock_register(&self->ptp_info, &aq_nic->ndev->dev);
	if (IS_ERR(clock)) {
		aq_nic_print(aq_nic, err, drv, "ptp_clock_register failed\n");
		err = -EFAULT;
		goto err_exit;
	}
	self->ptp_clock = clock;
	aq_ptp_tx_timeout_init(&self->ptp_tx_timeout);

	atomic_set(&self->offset_egress, 0);
	atomic_set(&self->offset_ingress, 0);

	netif_napi_add(aq_nic_get_ndev(aq_nic), &self->napi,
			aq_ptp_poll, AQ_CFG_NAPI_WEIGHT);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	self->num_vector = num_vec;
#endif
	self->idx_vector = idx_vec;

	aq_nic->aq_ptp = self;

	/* enable ptp counter */
	aq_utils_obj_set(&aq_nic->aq_hw->flags, AQ_HW_PTP_AVAILABLE);
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_fw_ops->enable_ptp(aq_nic->aq_hw, 1);
	aq_ptp_clock_init(aq_nic);
	mutex_unlock(&aq_nic->fwreq_mutex);

err_exit:
	return err;
}

/*
 * aq_ptp_stop - close the PTP device
 * @adapter: pointer to adapter struct
 *
 * completely destroy the PTP device, should only be called when the device is
 * being fully closed.
 */
void aq_ptp_unregister(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;

	if (!self)
		return;

	ptp_clock_unregister(self->ptp_clock);
}

void aq_ptp_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *self = aq_nic->aq_ptp;

	if (!self)
		return;

	/* disable ptp */
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_fw_ops->enable_ptp(aq_nic->aq_hw, 0);
	mutex_unlock(&aq_nic->fwreq_mutex);

	netif_napi_del(&self->napi);
	kfree(self);
	aq_nic->aq_ptp = NULL;
}

struct ptp_clock *aq_ptp_get_ptp_clock(struct aq_ptp_s *self)
{
	return self->ptp_clock;
}
#endif
