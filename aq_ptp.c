// SPDX-License-Identifier: GPL-2.0-only
/* Aquantia Corporation Network Driver
 * Copyright (C) 2014-2019 Aquantia Corporation. All rights reserved
 */

/* File aq_ptp.c:
 * Definition of functions for Linux PTP support.
 */

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>

#include "aq_nic.h"
#include "aq_ptp.h"
#include "aq_ring.h"
#include "aq_phy.h"
#include "aq_ethtool.h"
#include "aq_filters.h"

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)

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

#define POLL_SYNC_TIMER_MS 15

/* Coefficients of PID. Multiplier and divider are used for distinguish
 * more accuracy while calculating PID parts
 */
#define PTP_MULT_COEF_P  15LL
#define PTP_MULT_COEF_I   5LL
#define PTP_MULT_COEF_D   1LL
#define PTP_DIV_COEF     10LL
#define PTP_DIV_RATIO   100LL

#define ACCURACY  20

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
	unsigned int head;
	unsigned int tail;
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

	struct aq_rx_filter_l3l4 udp_filter;
	struct aq_rx_filter_l2 eth_type_filter;

	struct delayed_work poll_sync;
	u32 poll_timeout_ms;

	bool extts_pin_enabled;
	bool sync_time_enabled;
	u64 sync_time_value;
	bool sync_freq_enabled;
	u64 ext_sync_period;

	u64 last_sync1588_ts;

	/*PID related values*/
	s64 delta[3];
	s64 adjust[2];
	bool second_change;

	/*Describes ratio of current period to 1s*/
	s64 multiplier;
	s64 divider;
	/*end of PID related values*/
};

struct ptp_tm_offset {
	unsigned int mbps;
	int egress;
	int ingress;
};

static struct ptp_tm_offset ptp_offset[6];

void aq_ptp_tm_offset_set(struct aq_nic_s *aq_nic, unsigned int mbps)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int i, egress, ingress;

	if (!aq_ptp)
		return;

	egress = 0;
	ingress = 0;

	for (i = 0; i < ARRAY_SIZE(ptp_offset); i++) {
		if (mbps == ptp_offset[i].mbps) {
			egress = ptp_offset[i].egress;
			ingress = ptp_offset[i].ingress;
			break;
		}
	}

	atomic_set(&aq_ptp->offset_egress, egress);
	atomic_set(&aq_ptp->offset_ingress, ingress);
}

static int __aq_ptp_skb_put(struct ptp_skb_ring *ring, struct sk_buff *skb)
{
	unsigned int next_head = (ring->head + 1) % ring->size;

	if (next_head == ring->tail)
		return -ENOMEM;

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

	if (!buff)
		return -ENOMEM;

	spin_lock_init(&ring->lock);

	ring->buff = buff;
	ring->size = size;
	ring->head = 0;
	ring->tail = 0;

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

static void aq_ptp_tx_timeout_start(struct aq_ptp_s *aq_ptp)
{
	struct ptp_tx_timeout *timeout = &aq_ptp->ptp_tx_timeout;
	unsigned long flags;

	spin_lock_irqsave(&timeout->lock, flags);
	timeout->active = true;
	timeout->tx_start = jiffies;
	spin_unlock_irqrestore(&timeout->lock, flags);
}

static void aq_ptp_tx_timeout_update(struct aq_ptp_s *aq_ptp)
{
	if (!aq_ptp_skb_buf_len(&aq_ptp->skb_ring)) {
		struct ptp_tx_timeout *timeout = &aq_ptp->ptp_tx_timeout;
		unsigned long flags;

		spin_lock_irqsave(&timeout->lock, flags);
		timeout->active = false;
		spin_unlock_irqrestore(&timeout->lock, flags);
	}
}

static void aq_ptp_tx_timeout_check(struct aq_ptp_s *aq_ptp)
{
	struct ptp_tx_timeout *timeout = &aq_ptp->ptp_tx_timeout;
	unsigned long flags;
	bool timeout_flag;

	timeout_flag = false;

	spin_lock_irqsave(&timeout->lock, flags);
	if (timeout->active) {
		timeout_flag = time_is_before_jiffies(timeout->tx_start +
						      AQ_PTP_TX_TIMEOUT);
		/* reset active flag if timeout detected */
		if (timeout_flag)
			timeout->active = false;
	}
	spin_unlock_irqrestore(&timeout->lock, flags);

	if (timeout_flag) {
		aq_ptp_skb_ring_clean(&aq_ptp->skb_ring);
		netdev_err(aq_ptp->aq_nic->ndev,
			   "PTP Timeout. Clearing Tx Timestamp SKBs\n");
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
/* aq_ptp_adjfine
 * @ptp: the ptp clock structure
 * @ppb: parts per billion adjustment from base
 *
 * adjust the frequency of the ptp cycle counter by the
 * indicated ppb from the base frequency.
 */
static int aq_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;

	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_hw_ops->hw_adj_clock_freq(aq_nic->aq_hw,
					     scaled_ppm_to_ppb(scaled_ppm));
	mutex_unlock(&aq_nic->fwreq_mutex);

	return 0;
}
#endif

static int aq_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;

	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_hw_ops->hw_adj_clock_freq(aq_nic->aq_hw, ppb);
	mutex_unlock(&aq_nic->fwreq_mutex);

	return 0;
}

/* aq_ptp_adjtime
 * @ptp: the ptp clock structure
 * @delta: offset to adjust the cycle counter by
 *
 * adjust the timer by resetting the timecounter structure.
 */
static int aq_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	unsigned long flags;

	spin_lock_irqsave(&aq_ptp->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_adj_sys_clock(aq_nic->aq_hw, delta);
	spin_unlock_irqrestore(&aq_ptp->ptp_lock, flags);

	return 0;
}

/* aq_ptp_gettime
 * @ptp: the ptp clock structure
 * @ts: timespec structure to hold the current time value
 *
 * read the timecounter and return the correct value on ns,
 * after converting it into a struct timespec.
 */
static int aq_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	unsigned long flags;
	u64 ns;

	spin_lock_irqsave(&aq_ptp->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &ns);
	spin_unlock_irqrestore(&aq_ptp->ptp_lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

/* aq_ptp_settime
 * @ptp: the ptp clock structure
 * @ts: the timespec containing the new time for the cycle counter
 *
 * reset the timecounter to use a new base value instead of the kernel
 * wall timer value.
 */
static int aq_ptp_settime(struct ptp_clock_info *ptp,
			  const struct timespec64 *ts)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	unsigned long flags;
	u64 ns = timespec64_to_ns(ts);
	u64 now;

	spin_lock_irqsave(&aq_ptp->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &now);
	aq_nic->aq_hw_ops->hw_adj_sys_clock(aq_nic->aq_hw, (s64)ns - (s64)now);

	spin_unlock_irqrestore(&aq_ptp->ptp_lock, flags);

	return 0;
}

static void aq_ptp_convert_to_hwtstamp(struct aq_ptp_s *aq_ptp,
				       struct skb_shared_hwtstamps *hwtstamp,
				       u64 timestamp)
{
	memset(hwtstamp, 0, sizeof(*hwtstamp));
	hwtstamp->hwtstamp = ns_to_ktime(timestamp);
}

static int aq_ptp_hw_pin_conf(struct aq_nic_s *aq_nic, u32 pin_index, u64 start,
			      u64 period)
{
	if (period)
		netdev_dbg(aq_nic->ndev,
			   "Enable GPIO %d pulsing, start time %llu, period %u\n",
			   pin_index, start, (u32)period);
	else
		netdev_dbg(aq_nic->ndev,
			   "Disable GPIO %d pulsing, start time %llu, period %u\n",
			   pin_index, start, (u32)period);

	/* Notify hardware of request to being sending pulses.
	 * If period is ZERO then pulsen is disabled.
	 */
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_hw_ops->hw_gpio_pulse(aq_nic->aq_hw, pin_index,
					 start, (u32)period);
	mutex_unlock(&aq_nic->fwreq_mutex);

	return 0;
}

static int aq_ptp_perout_pin_configure(struct ptp_clock_info *ptp,
				       struct ptp_clock_request *rq, int on)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct ptp_clock_time *t = &rq->perout.period;
	struct ptp_clock_time *s = &rq->perout.start;
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u64 start, period;
	u32 pin_index = rq->perout.index;

	/* verify the request channel is there */
	if (pin_index >= ptp->n_per_out)
		return -EINVAL;

	/* we cannot support periods greater
	 * than 4 seconds due to reg limit
	 */
	if (t->sec > 4 || t->sec < 0)
		return -ERANGE;

	/* convert to unsigned 64b ns,
	 * verify we can put it in a 32b register
	 */
	period = on ? t->sec * NSEC_PER_SEC + t->nsec : 0;

	/* verify the value is in range supported by hardware */
	if (period > U32_MAX)
		return -ERANGE;
	/* convert to unsigned 64b ns */
	/* TODO convert to AQ time */
	start = on ? s->sec * NSEC_PER_SEC + s->nsec : 0;

	aq_ptp_hw_pin_conf(aq_nic, pin_index, start, period);

	return 0;
}

static int aq_ptp_pps_pin_configure(struct ptp_clock_info *ptp,
				    struct ptp_clock_request *rq, int on)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u64 start, period;
	u32 pin_index = 0;
	u32 rest = 0;

	/* verify the request channel is there */
	if (pin_index >= ptp->n_per_out)
		return -EINVAL;

	aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &start);
	div_u64_rem(start, NSEC_PER_SEC, &rest);
	period = on ? NSEC_PER_SEC : 0; /* PPS - pulse per second */
	start = on ? start - rest + NSEC_PER_SEC *
		(rest > 990000000LL ? 2 : 1) : 0;

	aq_ptp_hw_pin_conf(aq_nic, pin_index, start, period);

	return 0;
}

static void aq_ptp_extts_pin_ctrl(struct aq_ptp_s *aq_ptp)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u32 enable = 0;

	if (aq_ptp->extts_pin_enabled ||
	    aq_ptp->sync_time_enabled || aq_ptp->sync_freq_enabled)
		enable = 1;

	if (aq_nic->aq_hw_ops->hw_extts_gpio_enable)
		aq_nic->aq_hw_ops->hw_extts_gpio_enable(aq_nic->aq_hw, 0,
							enable);
}

static int aq_ptp_extts_pin_configure(struct ptp_clock_info *ptp,
				      struct ptp_clock_request *rq, int on)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);

	u32 pin_index = rq->extts.index;

	if (pin_index >= ptp->n_ext_ts)
		return -EINVAL;

	aq_ptp->extts_pin_enabled = !!on;
	if (on) {
		aq_ptp->poll_timeout_ms = POLL_SYNC_TIMER_MS;
		cancel_delayed_work_sync(&aq_ptp->poll_sync);
		schedule_delayed_work(&aq_ptp->poll_sync,
				      msecs_to_jiffies(aq_ptp->poll_timeout_ms));
	}

	aq_ptp_extts_pin_ctrl(aq_ptp);
	return 0;
}

/* aq_ptp_gpio_feature_enable
 * @ptp: the ptp clock structure
 * @rq: the requested feature to change
 * @on: whether to enable or disable the feature
 */
static int aq_ptp_gpio_feature_enable(struct ptp_clock_info *ptp,
				      struct ptp_clock_request *rq, int on)
{
	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		return aq_ptp_extts_pin_configure(ptp, rq, on);
	case PTP_CLK_REQ_PEROUT:
		return aq_ptp_perout_pin_configure(ptp, rq, on);
	case PTP_CLK_REQ_PPS:
		return aq_ptp_pps_pin_configure(ptp, rq, on);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

/* aq_ptp_verify
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

/* aq_ptp_tx_hwtstamp - utility function which checks for TX time stamp
 * @adapter: the private adapter struct
 *
 * if the timestamp is valid, we convert it into the timecounter ns
 * value, then store that result into the hwtstamps structure which
 * is passed up the network stack
 */
void aq_ptp_tx_hwtstamp(struct aq_nic_s *aq_nic, u64 timestamp)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	struct sk_buff *skb = aq_ptp_skb_get(&aq_ptp->skb_ring);
	struct skb_shared_hwtstamps hwtstamp;

	if (!skb) {
		netdev_err(aq_nic->ndev, "have timestamp but tx_queues empty\n");
		return;
	}

	timestamp += atomic_read(&aq_ptp->offset_egress);
	aq_ptp_convert_to_hwtstamp(aq_ptp, &hwtstamp, timestamp);
	skb_tstamp_tx(skb, &hwtstamp);
	dev_kfree_skb_any(skb);

	aq_ptp_tx_timeout_update(aq_ptp);
}

/* aq_ptp_rx_hwtstamp - utility function which checks for RX time stamp
 * @adapter: pointer to adapter struct
 * @skb: particular skb to send timestamp with
 *
 * if the timestamp is valid, we convert it into the timecounter ns
 * value, then store that result into the hwtstamps structure which
 * is passed up the network stack
 */
static void aq_ptp_rx_hwtstamp(struct aq_ptp_s *aq_ptp, struct sk_buff *skb,
			       u64 timestamp)
{
	timestamp -= atomic_read(&aq_ptp->offset_ingress);
	aq_ptp_convert_to_hwtstamp(aq_ptp, skb_hwtstamps(skb), timestamp);
}

void aq_ptp_hwtstamp_config_get(struct aq_ptp_s *aq_ptp,
				struct hwtstamp_config *config)
{
	*config = aq_ptp->hwtstamp_config;
}

static void aq_ptp_prepare_filters(struct aq_ptp_s *aq_ptp)
{
	aq_ptp->udp_filter.cmd = HW_ATL_RX_ENABLE_FLTR_L3L4 |
			       HW_ATL_RX_ENABLE_CMP_PROT_L4 |
			       HW_ATL_RX_UDP |
			       HW_ATL_RX_ENABLE_CMP_DEST_PORT_L4 |
			       HW_ATL_RX_HOST << HW_ATL_RX_ACTION_FL3F4_SHIFT |
			       HW_ATL_RX_ENABLE_QUEUE_L3L4 |
			       aq_ptp->ptp_rx.idx << HW_ATL_RX_QUEUE_FL3L4_SHIFT;
	aq_ptp->udp_filter.p_dst = PTP_EV_PORT;

	aq_ptp->eth_type_filter.ethertype = ETH_P_1588;
	aq_ptp->eth_type_filter.queue = aq_ptp->ptp_rx.idx;
}

int aq_ptp_hwtstamp_config_set(struct aq_ptp_s *aq_ptp,
			       struct hwtstamp_config *config)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	const struct aq_hw_ops *hw_ops;
	int err = 0;

	hw_ops = aq_nic->aq_hw_ops;
	if (config->tx_type == HWTSTAMP_TX_ON ||
	    config->rx_filter == HWTSTAMP_FILTER_PTP_V2_EVENT) {
		aq_ptp_prepare_filters(aq_ptp);
		if (hw_ops->hw_filter_l3l4_set) {
			err = hw_ops->hw_filter_l3l4_set(aq_nic->aq_hw,
							 &aq_ptp->udp_filter);
		}
		if (!err && hw_ops->hw_filter_l2_set) {
			err = hw_ops->hw_filter_l2_set(aq_nic->aq_hw,
						       &aq_ptp->eth_type_filter);
		}
		aq_utils_obj_set(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP);
	} else {
		aq_ptp->udp_filter.cmd &= ~HW_ATL_RX_ENABLE_FLTR_L3L4;
		if (hw_ops->hw_filter_l3l4_set) {
			err = hw_ops->hw_filter_l3l4_set(aq_nic->aq_hw,
							 &aq_ptp->udp_filter);
		}
		if (!err && hw_ops->hw_filter_l2_clear) {
			err = hw_ops->hw_filter_l2_clear(aq_nic->aq_hw,
							&aq_ptp->eth_type_filter);
		}
		aq_utils_obj_clear(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP);
	}

	if (err)
		return -EREMOTEIO;

	aq_ptp->hwtstamp_config = *config;

	return 0;
}

bool aq_ptp_ring(struct aq_nic_s *aq_nic, struct aq_ring_s *ring)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return false;

	return &aq_ptp->ptp_tx == ring ||
	       &aq_ptp->ptp_rx == ring || &aq_ptp->hwts_rx == ring;
}

u16 aq_ptp_extract_ts(struct aq_nic_s *aq_nic, struct sk_buff *skb, u8 *p,
		      unsigned int len)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	u64 timestamp = 0;
	u16 ret = aq_nic->aq_hw_ops->rx_extract_ts(aq_nic->aq_hw,
						   p, len, &timestamp);

	if (ret > 0)
		aq_ptp_rx_hwtstamp(aq_ptp, skb, timestamp);

	return ret;
}

static int aq_ptp_poll(struct napi_struct *napi, int budget)
{
	struct aq_ptp_s *aq_ptp = container_of(napi, struct aq_ptp_s, napi);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	bool was_cleaned = false;
	int work_done = 0;
	int err;

	/* Processing PTP TX traffic */
	err = aq_nic->aq_hw_ops->hw_ring_tx_head_update(aq_nic->aq_hw,
							&aq_ptp->ptp_tx);
	if (err < 0)
		goto err_exit;

	if (aq_ptp->ptp_tx.sw_head != aq_ptp->ptp_tx.hw_head) {
		aq_ring_tx_clean(&aq_ptp->ptp_tx);

		was_cleaned = true;
	}

	/* Processing HW_TIMESTAMP RX traffic */
	err = aq_nic->aq_hw_ops->hw_ring_hwts_rx_receive(aq_nic->aq_hw,
							 &aq_ptp->hwts_rx);
	if (err < 0)
		goto err_exit;

	if (aq_ptp->hwts_rx.sw_head != aq_ptp->hwts_rx.hw_head) {
		aq_ring_hwts_rx_clean(&aq_ptp->hwts_rx, aq_nic);

		err = aq_nic->aq_hw_ops->hw_ring_hwts_rx_fill(aq_nic->aq_hw,
							      &aq_ptp->hwts_rx);
		if (err < 0)
			goto err_exit;

		was_cleaned = true;
	}

	/* Processing PTP RX traffic */
	err = aq_nic->aq_hw_ops->hw_ring_rx_receive(aq_nic->aq_hw,
						    &aq_ptp->ptp_rx);
	if (err < 0)
		goto err_exit;

	if (aq_ptp->ptp_rx.sw_head != aq_ptp->ptp_rx.hw_head) {
		unsigned int sw_tail_old;

		err = aq_ring_rx_clean(&aq_ptp->ptp_rx, napi, &work_done, budget);
		if (err < 0)
			goto err_exit;

		sw_tail_old = aq_ptp->ptp_rx.sw_tail;
		err = aq_ring_rx_fill(&aq_ptp->ptp_rx);
		if (err < 0)
			goto err_exit;

		err = aq_nic->aq_hw_ops->hw_ring_rx_fill(aq_nic->aq_hw,
							 &aq_ptp->ptp_rx,
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
					BIT_ULL(aq_ptp->ptp_ring_param.vec_idx));
	}

err_exit:
	return work_done;
}

static irqreturn_t aq_ptp_isr(int irq, void *private)
{
	struct aq_ptp_s *aq_ptp = private;
	int err = 0;

	if (!aq_ptp) {
		err = -EINVAL;
		goto err_exit;
	}
	napi_schedule(&aq_ptp->napi);

err_exit:
	return err >= 0 ? IRQ_HANDLED : IRQ_NONE;
}

int aq_ptp_xmit(struct aq_nic_s *aq_nic, struct sk_buff *skb)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	struct aq_ring_s *ring = &aq_ptp->ptp_tx;
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

	err = aq_ptp_skb_put(&aq_ptp->skb_ring, skb);
	if (err) {
		netdev_err(aq_nic->ndev, "SKB Ring is overflow (%u)!\n",
			   ring->size);
		return NETDEV_TX_BUSY;
	}
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	aq_ptp_tx_timeout_start(aq_ptp);
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
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	aq_ptp_tx_timeout_check(aq_ptp);
}

int aq_ptp_irq_alloc(struct aq_nic_s *aq_nic)
{
	struct pci_dev *pdev = aq_nic->pdev;
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int err = 0;

	if (!aq_ptp)
		return 0;

	if (pdev->msix_enabled || pdev->msi_enabled) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
		err = request_irq(aq_ptp->num_vector, aq_ptp_isr, 0,
				aq_nic->ndev->name, aq_ptp);
#else
		err = request_irq(pci_irq_vector(pdev, aq_ptp->idx_vector),
				  aq_ptp_isr, 0, aq_nic->ndev->name, aq_ptp);
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
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	struct pci_dev *pdev = aq_nic->pdev;
#endif

	if (!aq_ptp)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	free_irq(pci_irq_vector(pdev, aq_ptp->idx_vector), aq_ptp);
#else
	free_irq(aq_ptp->num_vector, aq_ptp);
#endif
}

int aq_ptp_ring_init(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int err = 0;

	if (!aq_ptp)
		return 0;

	err = aq_ring_init(&aq_ptp->ptp_tx);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_tx_init(aq_nic->aq_hw,
						 &aq_ptp->ptp_tx,
						 &aq_ptp->ptp_ring_param);
	if (err < 0)
		goto err_exit;

	err = aq_ring_init(&aq_ptp->ptp_rx);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_rx_init(aq_nic->aq_hw,
						 &aq_ptp->ptp_rx,
						 &aq_ptp->ptp_ring_param);
	if (err < 0)
		goto err_exit;

	err = aq_ring_rx_fill(&aq_ptp->ptp_rx);
	if (err < 0)
		goto err_rx_free;
	err = aq_nic->aq_hw_ops->hw_ring_rx_fill(aq_nic->aq_hw,
						 &aq_ptp->ptp_rx,
						 0U);
	if (err < 0)
		goto err_rx_free;

	err = aq_ring_init(&aq_ptp->hwts_rx);
	if (err < 0)
		goto err_rx_free;
	err = aq_nic->aq_hw_ops->hw_ring_rx_init(aq_nic->aq_hw,
						 &aq_ptp->hwts_rx,
						 &aq_ptp->ptp_ring_param);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_hwts_rx_fill(aq_nic->aq_hw,
						      &aq_ptp->hwts_rx);
	if (err < 0)
		goto err_exit;

	return err;

err_rx_free:
	aq_ring_rx_deinit(&aq_ptp->ptp_rx);
err_exit:
	return err;
}

int aq_ptp_ring_start(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int err = 0;

	if (!aq_ptp)
		return 0;

	err = aq_nic->aq_hw_ops->hw_ring_tx_start(aq_nic->aq_hw, &aq_ptp->ptp_tx);
	if (err < 0)
		goto err_exit;

	err = aq_nic->aq_hw_ops->hw_ring_rx_start(aq_nic->aq_hw, &aq_ptp->ptp_rx);
	if (err < 0)
		goto err_exit;

	err = aq_nic->aq_hw_ops->hw_ring_rx_start(aq_nic->aq_hw,
						  &aq_ptp->hwts_rx);
	if (err < 0)
		goto err_exit;

	napi_enable(&aq_ptp->napi);

err_exit:
	return err;
}

void aq_ptp_ring_stop(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	aq_nic->aq_hw_ops->hw_ring_tx_stop(aq_nic->aq_hw, &aq_ptp->ptp_tx);
	aq_nic->aq_hw_ops->hw_ring_rx_stop(aq_nic->aq_hw, &aq_ptp->ptp_rx);

	aq_nic->aq_hw_ops->hw_ring_rx_stop(aq_nic->aq_hw, &aq_ptp->hwts_rx);

	napi_disable(&aq_ptp->napi);
}

void aq_ptp_ring_deinit(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp || !aq_ptp->ptp_tx.aq_nic || !aq_ptp->ptp_rx.aq_nic)
		return;

	aq_ring_tx_clean(&aq_ptp->ptp_tx);
	aq_ring_rx_deinit(&aq_ptp->ptp_rx);
}

#define PTP_8TC_RING_IDX             8
#define PTP_4TC_RING_IDX            16
#define PTP_HWST_RING_IDX           31

int aq_ptp_ring_alloc(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	unsigned int tx_ring_idx, rx_ring_idx;
	struct aq_ring_s *hwts;
	u32 tx_tc_mode, rx_tc_mode;
	struct aq_ring_s *ring;
	int err;

	if (!aq_ptp)
		return 0;

	/* Index must to be 8 (8 TCs) or 16 (4 TCs).
	 * It depends from Traffic Class mode.
	 */
	aq_nic->aq_hw_ops->hw_tx_tc_mode_get(aq_nic->aq_hw, &tx_tc_mode);
	if (tx_tc_mode == 0)
		tx_ring_idx = PTP_8TC_RING_IDX;
	else
		tx_ring_idx = PTP_4TC_RING_IDX;

	ring = aq_ring_tx_alloc(&aq_ptp->ptp_tx, aq_nic,
				tx_ring_idx, &aq_nic->aq_nic_cfg);
	if (!ring) {
		err = -ENOMEM;
		goto err_exit;
	}

	aq_nic->aq_hw_ops->hw_rx_tc_mode_get(aq_nic->aq_hw, &rx_tc_mode);
	if (rx_tc_mode == 0)
		rx_ring_idx = PTP_8TC_RING_IDX;
	else
		rx_ring_idx = PTP_4TC_RING_IDX;

	ring = aq_ring_rx_alloc(&aq_ptp->ptp_rx, aq_nic,
				rx_ring_idx, &aq_nic->aq_nic_cfg);
	if (!ring) {
		err = -ENOMEM;
		goto err_exit_ptp_tx;
	}

	hwts = aq_ring_hwts_rx_alloc(&aq_ptp->hwts_rx, aq_nic, PTP_HWST_RING_IDX,
				     aq_nic->aq_nic_cfg.rxds,
				     aq_nic->aq_nic_cfg.aq_hw_caps->rxd_size);
	if (!hwts) {
		err = -ENOMEM;
		goto err_exit_ptp_rx;
	}

	err = aq_ptp_skb_ring_init(&aq_ptp->skb_ring, aq_nic->aq_nic_cfg.rxds);
	if (err != 0) {
		err = -ENOMEM;
		goto err_exit_hwts_rx;
	}

	aq_ptp->ptp_ring_param.vec_idx = aq_ptp->idx_vector;
	aq_ptp->ptp_ring_param.cpu = aq_ptp->ptp_ring_param.vec_idx +
			aq_nic_get_cfg(aq_nic)->aq_rss.base_cpu_number;
	cpumask_set_cpu(aq_ptp->ptp_ring_param.cpu,
			&aq_ptp->ptp_ring_param.affinity_mask);

	return 0;

err_exit_hwts_rx:
	aq_ring_free(&aq_ptp->hwts_rx);
err_exit_ptp_rx:
	aq_ring_free(&aq_ptp->ptp_rx);
err_exit_ptp_tx:
	aq_ring_free(&aq_ptp->ptp_tx);
err_exit:
	return err;
}

void aq_ptp_ring_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	aq_ring_free(&aq_ptp->ptp_tx);
	aq_ring_free(&aq_ptp->ptp_rx);
	aq_ring_free(&aq_ptp->hwts_rx);

	aq_ptp_skb_ring_release(&aq_ptp->skb_ring);
}

#define MAX_PTP_GPIO_COUNT 4

static struct ptp_clock_info aq_ptp_clock = {
	.owner		= THIS_MODULE,
	.name		= "atlantic ptp",
	.max_adj	= 999999999,
	.n_ext_ts	= 0,
	.pps		= 0,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	.adjfine	= aq_ptp_adjfine,
#else
	.adjfreq	= aq_ptp_adjfreq,
#endif
	.adjtime	= aq_ptp_adjtime,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	.gettime64	= aq_ptp_gettime,
	.settime64	= aq_ptp_settime,
#else
	.gettime	= aq_ptp_gettime,
	.settime	= aq_ptp_settime,
#endif
	.n_per_out	= 0,
	.enable		= aq_ptp_gpio_feature_enable,
	.n_pins		= 0,
	.verify		= aq_ptp_verify,
	.pin_config	= NULL,
};

#define ptp_offset_init(__idx, __mbps, __egress, __ingress)   do { \
		ptp_offset[__idx].mbps = (__mbps); \
		ptp_offset[__idx].egress = (__egress); \
		ptp_offset[__idx].ingress = (__ingress); } \
		while (0)

static void aq_ptp_offset_init_from_fw(const struct hw_atl_ptp_offset *offsets)
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

static void aq_ptp_offset_init(const struct hw_atl_ptp_offset *offsets)
{
	memset(ptp_offset, 0, sizeof(ptp_offset));

	if (aq_ptp_offset_forced) {
		aq_ptp_offset_init_from_params(1);
	} else {
		aq_ptp_offset_init_from_fw(offsets);
		aq_ptp_offset_init_from_params(0);
	}
}

static void aq_ptp_gpio_init(struct ptp_clock_info *info,
			     struct hw_atl_info *hw_info)
{
	struct ptp_pin_desc pin_desc[MAX_PTP_GPIO_COUNT];
	u32 extts_pin_cnt = 0;
	u32 out_pin_cnt = 0;
	u32 i;

	memset(pin_desc, 0, sizeof(pin_desc));

	for (i = 0; i < MAX_PTP_GPIO_COUNT - 1; i++) {
		if (hw_info->gpio_pin[i] ==
		    (GPIO_PIN_FUNCTION_PTP0 + out_pin_cnt)) {
			snprintf(pin_desc[out_pin_cnt].name,
				 sizeof(pin_desc[out_pin_cnt].name),
				 "AQ_GPIO%d", i);
			pin_desc[out_pin_cnt].index = out_pin_cnt;
			pin_desc[out_pin_cnt].chan = out_pin_cnt;
			pin_desc[out_pin_cnt++].func = PTP_PF_PEROUT;
		}
	}

	info->n_per_out = out_pin_cnt;

	if (hw_info->caps_ex & BIT(CAPS_EX_PHY_CTRL_TS_PIN)) {
		extts_pin_cnt += 1;

		snprintf(pin_desc[out_pin_cnt].name,
			 sizeof(pin_desc[out_pin_cnt].name),
			  "AQ_GPIO%d", out_pin_cnt);
		pin_desc[out_pin_cnt].index = out_pin_cnt;
		pin_desc[out_pin_cnt].chan = 0;
		pin_desc[out_pin_cnt].func = PTP_PF_EXTTS;
	}

	info->n_pins = out_pin_cnt + extts_pin_cnt;
	info->n_ext_ts = extts_pin_cnt;

	if (!info->n_pins)
		return;

	info->pin_config = kcalloc(info->n_pins, sizeof(struct ptp_pin_desc),
				   GFP_KERNEL);

	if (!info->pin_config)
		return;

	memcpy(info->pin_config, &pin_desc,
	       sizeof(struct ptp_pin_desc) * info->n_pins);
}

void aq_ptp_clock_init(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	aq_ptp_settime(&aq_ptp->ptp_info, &ts);
}

static void aq_ptp_poll_sync_work_cb(struct work_struct *w);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
int aq_ptp_init(struct aq_nic_s *aq_nic, unsigned int idx_vec,
		unsigned int num_vec)
#else
int aq_ptp_init(struct aq_nic_s *aq_nic, unsigned int idx_vec)
#endif
{
	struct hw_atl_utils_mbox mbox;
	struct ptp_clock *clock;
	struct aq_ptp_s *aq_ptp;
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

	aq_ptp = kzalloc(sizeof(*aq_ptp), GFP_KERNEL);
	if (!aq_ptp) {
		err = -ENOMEM;
		goto err_exit;
	}

	aq_ptp->aq_nic = aq_nic;

	spin_lock_init(&aq_ptp->ptp_lock);
	spin_lock_init(&aq_ptp->ptp_ring_lock);

	aq_ptp->ptp_info = aq_ptp_clock;
	aq_ptp_gpio_init(&aq_ptp->ptp_info, &mbox.info);
	clock = ptp_clock_register(&aq_ptp->ptp_info, &aq_nic->ndev->dev);
	if (IS_ERR(clock)) {
		netdev_err(aq_nic->ndev, "ptp_clock_register failed\n");
		err = PTR_ERR(clock);
		goto err_exit;
	}
	aq_ptp->ptp_clock = clock;
	aq_ptp_tx_timeout_init(&aq_ptp->ptp_tx_timeout);

	atomic_set(&aq_ptp->offset_egress, 0);
	atomic_set(&aq_ptp->offset_ingress, 0);

	netif_napi_add(aq_nic_get_ndev(aq_nic), &aq_ptp->napi,
		       aq_ptp_poll, AQ_CFG_NAPI_WEIGHT);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	aq_ptp->num_vector = num_vec;
#endif
	aq_ptp->idx_vector = idx_vec;

	aq_nic->aq_ptp = aq_ptp;

	/* enable ptp counter */
	aq_utils_obj_set(&aq_nic->aq_hw->flags, AQ_HW_PTP_AVAILABLE);
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_fw_ops->enable_ptp(aq_nic->aq_hw, 1);
	aq_ptp_clock_init(aq_nic);
	mutex_unlock(&aq_nic->fwreq_mutex);

	INIT_DELAYED_WORK(&aq_ptp->poll_sync, &aq_ptp_poll_sync_work_cb);
	aq_ptp->eth_type_filter.location =
			aq_nic_reserve_filter(aq_nic, aq_rx_filter_ethertype);
	aq_ptp->udp_filter.location =
			aq_nic_reserve_filter(aq_nic, aq_rx_filter_l3l4);

	return 0;

err_exit:
	if (aq_ptp)
		kfree(aq_ptp->ptp_info.pin_config);
	kfree(aq_ptp);
	aq_nic->aq_ptp = NULL;
	return err;
}

void aq_ptp_unregister(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	ptp_clock_unregister(aq_ptp->ptp_clock);
}

void aq_ptp_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	aq_nic_release_filter(aq_nic, aq_rx_filter_ethertype,
			      aq_ptp->eth_type_filter.location);
	aq_nic_release_filter(aq_nic, aq_rx_filter_l3l4,
			      aq_ptp->udp_filter.location);
	cancel_delayed_work_sync(&aq_ptp->poll_sync);
	/* disable ptp */
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_fw_ops->enable_ptp(aq_nic->aq_hw, 0);
	mutex_unlock(&aq_nic->fwreq_mutex);

	kfree(aq_ptp->ptp_info.pin_config);

	netif_napi_del(&aq_ptp->napi);
	kfree(aq_ptp);
	aq_nic->aq_ptp = NULL;
}

struct ptp_clock *aq_ptp_get_ptp_clock(struct aq_ptp_s *aq_ptp)
{
	return aq_ptp->ptp_clock;
}

/* PTP external GPIO nanoseconds count */
static uint64_t aq_ptp_get_sync1588_ts(struct aq_nic_s *aq_nic)
{
	u64 ts = 0;

	if (aq_nic->aq_hw_ops->hw_get_sync_ts)
		aq_nic->aq_hw_ops->hw_get_sync_ts(aq_nic->aq_hw, &ts);

	return ts;
}

static void aq_ptp_pid_reset(struct aq_ptp_s *aq_ptp)
{
	memset(aq_ptp->delta, 0, sizeof(aq_ptp->delta));
	memset(aq_ptp->adjust, 0, sizeof(aq_ptp->adjust));
	aq_ptp->second_change = false;
}

static void aq_ptp_start_work(struct aq_ptp_s *aq_ptp)
{
	if (!aq_ptp->sync_time_enabled &&
	    !aq_ptp->sync_freq_enabled && !aq_ptp->extts_pin_enabled)
		return;

	if (aq_ptp->sync_time_enabled || aq_ptp->extts_pin_enabled)
		aq_ptp->poll_timeout_ms = POLL_SYNC_TIMER_MS;
	else
		/* If we need only clock sync poll TS at least
		 * 3 times per period
		 */
		aq_ptp->poll_timeout_ms = div64_u64(aq_ptp->ext_sync_period,
						    NSEC_PER_MSEC * 3);

	aq_ptp->last_sync1588_ts = aq_ptp_get_sync1588_ts(aq_ptp->aq_nic);
	schedule_delayed_work(&aq_ptp->poll_sync,
			      msecs_to_jiffies(aq_ptp->poll_timeout_ms));
}

/* Store new PTP time and wait until sync1588 pin triggered */
int aq_ptp_configure_sync1588(struct aq_nic_s *aq_nic,
			      struct aq_ptp_sync1588 *sync1588)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int err = 0;

	if (!aq_ptp) {
		err = -ENOTSUPP;
		goto err_exit;
	}

	if (aq_ptp->ptp_info.n_ext_ts == 0) {
		netdev_info(aq_nic->ndev,
			"Not supported, since EXT TS pin was not advertised");
		err = -ENOTSUPP;
		goto err_exit;
	}

	cancel_delayed_work_sync(&aq_ptp->poll_sync);

	switch (sync1588->action) {
	case aq_sync_cntr_set:
		netdev_info(aq_nic->ndev, "Enable sync time on event:%llu",
			    sync1588->time_ns);
		aq_ptp->sync_time_enabled = true;
		aq_ptp->sync_time_value = sync1588->time_ns;
		break;
	case 0:
		netdev_info(aq_nic->ndev, "Disable sync time on event");
		aq_ptp->sync_time_enabled = false;
		break;
	default:
		err = -ENOTSUPP;
		goto err_exit;
	}

	if (sync1588->clock_sync_en) {
		if (sync1588->sync_pulse_ms < 50 ||
		    sync1588->sync_pulse_ms > MSEC_PER_SEC) {
			netdev_err(aq_nic->ndev,
				   "Sync pulse ms should not be equal less"
				   " than 50ms or higher than 1s");
			err = -EINVAL;
			goto err_exit;
		}

		netdev_info(aq_nic->ndev,
			    "Enable sync clock with ext signal with period: %u",
			    sync1588->sync_pulse_ms);

		aq_ptp->sync_freq_enabled = true;
		aq_ptp->ext_sync_period = (uint64_t)sync1588->sync_pulse_ms *
					  NSEC_PER_MSEC;

		aq_ptp->multiplier = div64_s64(NSEC_PER_SEC * PTP_DIV_RATIO,
					       aq_ptp->ext_sync_period);
		aq_ptp->divider = PTP_DIV_RATIO;
	} else {
		netdev_info(aq_nic->ndev, "Disable sync clock");
		aq_ptp->sync_freq_enabled = false;
		aq_ptp_pid_reset(aq_ptp);
	}

	aq_ptp_extts_pin_ctrl(aq_ptp);
	if (aq_nic->aq_hw->aq_link_status.mbps)
		aq_ptp_start_work(aq_ptp);

err_exit:
	return err;
}

int aq_ptp_link_change(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return 0;

	if (aq_nic->aq_hw->aq_link_status.mbps) {
		aq_ptp_pid_reset(aq_ptp);
		aq_ptp_start_work(aq_ptp);
	} else {
		cancel_delayed_work_sync(&aq_ptp->poll_sync);
		aq_ptp_pid_reset(aq_ptp);
	}

	return 0;
}

static int aq_ptp_pid(struct aq_ptp_s *aq_ptp)
{
	s64 p = PTP_MULT_COEF_P * aq_ptp->multiplier *
		(aq_ptp->delta[0] - aq_ptp->delta[1]);
	s64 integral = PTP_MULT_COEF_I * aq_ptp->multiplier * aq_ptp->delta[1];
	s64 diff = PTP_MULT_COEF_D * aq_ptp->multiplier *
		   (aq_ptp->delta[0] - 2 * aq_ptp->delta[1] + aq_ptp->delta[2]);
	s64 adjust0 = p + integral + diff;

	netdev_dbg(aq_ptp->aq_nic->ndev,
		   "p = %lld, integral = %lld, diff = %lld",
		   div64_s64(p, PTP_DIV_COEF * aq_ptp->divider),
		   div64_s64(integral, PTP_DIV_COEF * aq_ptp->divider),
		   div64_s64(diff, PTP_DIV_COEF * aq_ptp->divider));

	adjust0 = div64_s64(adjust0, PTP_DIV_COEF * aq_ptp->divider);
	aq_ptp->adjust[0] = adjust0 + aq_ptp->adjust[1];

	aq_ptp->adjust[1] = aq_ptp->adjust[0];
	aq_ptp->delta[2] = aq_ptp->delta[1];
	aq_ptp->delta[1] = aq_ptp->delta[0];
	netdev_dbg(aq_ptp->aq_nic->ndev, "delta = %lld, adjust = %lld",
		   aq_ptp->delta[0], aq_ptp->adjust[0]);

	return 0;
}

static bool aq_ptp_sync_ts_updated(struct aq_ptp_s *aq_ptp, u64 *new_ts)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u64 sync_ts2;
	u64 sync_ts;

	sync_ts = aq_ptp_get_sync1588_ts(aq_nic);

	if (sync_ts != aq_ptp->last_sync1588_ts) {
		sync_ts2 = aq_ptp_get_sync1588_ts(aq_nic);
		if (sync_ts != sync_ts2) {
			sync_ts = sync_ts2;
			sync_ts2 = aq_ptp_get_sync1588_ts(aq_nic);
			if (sync_ts != sync_ts2) {
				netdev_err(aq_nic->ndev,
					   "%s: Unable to get correct GPIO TS",
					   __func__);
				sync_ts = 0;
			}
		}

		*new_ts = sync_ts;
		return true;
	}
	return false;
}

bool aq_ptp_ts_valid(struct aq_ptp_s *aq_ptp, u64 diff)
{
	/* check we get valid TS, let's use simple check: if difference of
	 * ts_diff and expected period more than half of expected period it
	 * means we've got invalid TS
	 */
	return abs((int64_t)diff - aq_ptp->ext_sync_period) <
	       div64_u64(aq_ptp->ext_sync_period, 3);
}

/* Check whether sync1588 pin was triggered, and set stored new PTP time */
static int aq_ptp_check_sync1588(struct aq_ptp_s *aq_ptp)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u64 sync_ts;

	 /* Sync1588 pin was triggered */
	if (aq_ptp_sync_ts_updated(aq_ptp, &sync_ts)) {
		netdev_dbg(aq_nic->ndev, "%s: sync1588 triggered TS: %llu",
			   __func__, sync_ts);
		netdev_dbg(aq_nic->ndev, "%s: sync1588 last sync TS: %llu",
			   __func__, aq_ptp->last_sync1588_ts);
		netdev_dbg(aq_nic->ndev, "%s: Diff TS: %llu",
			   __func__, sync_ts - aq_ptp->last_sync1588_ts);

		if (aq_ptp->sync_time_enabled) {
			unsigned long flags;

			aq_ptp->sync_time_enabled = false;
			spin_lock_irqsave(&aq_ptp->ptp_lock, flags);
			aq_nic->aq_hw_ops->hw_set_sys_clock(aq_nic->aq_hw,
							aq_ptp->sync_time_value,
							sync_ts);
			spin_unlock_irqrestore(&aq_ptp->ptp_lock, flags);
		}
		if (aq_ptp->extts_pin_enabled) {
			struct ptp_clock_event ptp_event;
			u64 time = 0;

			aq_nic->aq_hw_ops->hw_ts_to_sys_clock(aq_nic->aq_hw,
							      sync_ts, &time);
			ptp_event.index = aq_ptp->ptp_info.n_pins - 1;
			ptp_event.timestamp = time;

			ptp_event.type = PTP_CLOCK_EXTTS;
			ptp_clock_event(aq_ptp->ptp_clock, &ptp_event);
		}

		if (aq_ptp->sync_freq_enabled) {
			u64 ts_diff = sync_ts - aq_ptp->last_sync1588_ts;

			if (!aq_ptp->second_change) {
				aq_ptp->second_change = true;
				goto skip_sync;
			}

			if (!aq_ptp_ts_valid(aq_ptp, ts_diff)) {
				netdev_err(aq_nic->ndev,
					"Invalid TS got, reset synchronization"
					" algorithm: TS diff: %llu,"
					" expected: about %llu",
					ts_diff, aq_ptp->ext_sync_period);
				aq_ptp_pid_reset(aq_ptp);
				aq_ptp_adjfreq(&aq_ptp->ptp_info, 0);
				goto skip_sync;
			}
			aq_ptp->delta[0] += ts_diff;
			aq_ptp->delta[0] -= aq_ptp->ext_sync_period;
			aq_ptp_pid(aq_ptp);

			/* Apply adjust in case if current delta more than 20 or
			 * changing of delta more than 20 (speed of delta
			 * changing)
			 */
			if (abs(aq_ptp->delta[0]) > ACCURACY ||
			    abs(aq_ptp->delta[1] - aq_ptp->delta[2]) > ACCURACY)
				aq_ptp_adjfreq(&aq_ptp->ptp_info,
					       -aq_ptp->adjust[0]);
		}

skip_sync:
		aq_ptp->last_sync1588_ts = sync_ts;
	}

	return 0;
}

static void aq_ptp_poll_sync_work_cb(struct work_struct *w)
{
	struct delayed_work *dw = to_delayed_work(w);
	struct aq_ptp_s *aq_ptp = container_of(dw, struct aq_ptp_s, poll_sync);

	aq_ptp_check_sync1588(aq_ptp);

	if (aq_ptp->sync_time_enabled ||
	    aq_ptp->sync_freq_enabled || aq_ptp->extts_pin_enabled) {
		unsigned long timeout = msecs_to_jiffies(aq_ptp->poll_timeout_ms);

		schedule_delayed_work(&aq_ptp->poll_sync, timeout);
	}
}

int aq_configure_sync1588(struct net_device *ndev,
			  struct aq_ptp_sync1588 *sync1588)
{
	struct aq_nic_s *aq_nic = NULL;

	if (!ndev)
		return -EINVAL;

	if (ndev->ethtool_ops != &aq_ethtool_ops)
		return -EINVAL;

	aq_nic = netdev_priv(ndev);
	if (!aq_nic)
		return -EINVAL;

	return aq_ptp_configure_sync1588(aq_nic, sync1588);
}
EXPORT_SYMBOL_GPL(aq_configure_sync1588);

#endif
