// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
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

#include "aq_hw_utils.h"
#include "aq_nic.h"
#include "aq_ptp.h"
#include "aq_ring.h"
#include "aq_phy.h"
#include "aq_ethtool.h"
#include "aq_filters.h"

#if IS_REACHABLE(CONFIG_PTP_1588_CLOCK)

#include <linux/moduleparam.h>
#include <linux/ptp_clock_kernel.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0) || RHEL_RELEASE_CODE
#include <linux/timecounter.h>
#endif
#include <linux/clocksource.h>

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

#define PTP_UDP_FILTERS_CNT 4

#define PTP_IPV4_MC_ADDR1 0xE0000181
#define PTP_IPV4_MC_ADDR2 0xE000006B

#define PTP_IPV6_MC_ADDR10 0xFF0E
#define PTP_IPV6_MC_ADDR14 0x0181
#define PTP_IPV6_MC_ADDR20 0xFF02
#define PTP_IPV6_MC_ADDR24 0x006B

static unsigned int aq_ptp_gpio_hightime = 100000;
module_param_named(aq_ptp_gpio_hightime, aq_ptp_gpio_hightime, uint, 0644);
MODULE_PARM_DESC(aq_ptp_gpio_hightime, "PTP GPIO high time");

enum ptp_extts_action {
	ptp_extts_disabled = 0,
	ptp_extts_user,
	ptp_extts_timesync,
	ptp_extts_freqsync
};

enum ptp_perout_action {
	ptp_perout_disabled = 0,
	ptp_perout_enabled,
	ptp_perout_pps,
};

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

struct aq_ptp_pid {
	bool first_diff;
	uint64_t last_sync1588_ts;
	u64 ext_sync_period;

	/*PID related values*/
	s64 delta[3];
	s64 adjust[2];

	/*Describes ratio of current period to 1s*/
	s64 multiplier;
	s64 divider;
};

struct ptp_tm_offset {
	unsigned int mbps;
	int egress;
	int ingress;
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

	unsigned int idx_ptp_vector;
	unsigned int idx_gpio_vector;
	struct napi_struct napi;

	struct aq_ring_s ptp_tx;
	struct aq_ring_s ptp_rx;
	struct aq_ring_s hwts_rx; //ATL1 FW

	struct ptp_skb_ring skb_ring;

	struct aq_rx_filter_l3l4 udp_filter[PTP_UDP_FILTERS_CNT];
	struct aq_rx_filter_l2 eth_type_filter;

	struct delayed_work poll_sync;
	u32 poll_timeout_ms;

	bool extts_pin_enabled;
	u64 sync_time_value;

	/* TSG clock selection: 0 - PTP, 1 - PTM */
	u32 ptp_clock_sel;

	struct aq_ptp_pid pid;

	bool a1_ptp;
	bool a2_ptp;

	struct ptp_tm_offset ptp_offset[6];
};

static int aq_ptp_extts_pin_configure(struct ptp_clock_info *ptp,
				      u32 n_pin, enum ptp_extts_action action);
static int aq_pps_reconfigure(struct aq_ptp_s *aq_ptp);

void aq_ptp_offset_get(struct aq_ptp_s *aq_ptp,
		       unsigned int mbps, int *egress, int *ingress)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(aq_ptp->ptp_offset); i++) {
		if (mbps == aq_ptp->ptp_offset[i].mbps) {
			*egress = aq_ptp->ptp_offset[i].egress;
			*ingress = aq_ptp->ptp_offset[i].ingress;
			break;
		}
	}
}

void aq_ptp_tm_offset_set(struct aq_nic_s *aq_nic, unsigned int mbps)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int i, egress, ingress;

	if (!aq_ptp)
		return;

	egress = 0;
	ingress = 0;

	for (i = 0; i < ARRAY_SIZE(aq_ptp->ptp_offset); i++) {
		if (mbps == aq_ptp->ptp_offset[i].mbps) {
			egress = aq_ptp->ptp_offset[i].egress;
			ingress = aq_ptp->ptp_offset[i].ingress;
			break;
		}
	}

	atomic_set(&aq_ptp->offset_egress, egress);
	atomic_set(&aq_ptp->offset_ingress, ingress);

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "Offsets: egress = %d ingress = %d\n", egress, ingress);
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

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "AQ PTP Adj Freq 0x%x\n", ppb);
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

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "AQ PTP Adj Time 0x%llx\n", delta);
	spin_lock_irqsave(&aq_ptp->ptp_lock, flags);
	aq_nic->aq_hw_ops->hw_adj_sys_clock(aq_nic->aq_hw, delta);
	spin_unlock_irqrestore(&aq_ptp->ptp_lock, flags);

	aq_pps_reconfigure(aq_ptp);

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

	aq_pps_reconfigure(aq_ptp);

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "AQ PTP Set time: new %llu\n", ns);

	return 0;
}

static void aq_ptp_convert_to_hwtstamp(struct aq_ptp_s *aq_ptp,
				       struct skb_shared_hwtstamps *hwtstamp,
				       u64 timestamp)
{
	memset(hwtstamp, 0, sizeof(*hwtstamp));
	hwtstamp->hwtstamp = ns_to_ktime(timestamp);
}

static bool aq_ptp_event_ts_updated(struct aq_ptp_s *aq_ptp, u32 clk_sel,
				    u64 prev_ts, u64 *new_ts, u32 *cnt)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	uint64_t event_ts2;
	uint64_t event_ts;

	event_ts = aq_nic->aq_hw_ops->hw_ptp_gpio_get_event(aq_nic->aq_hw,
							    clk_sel, cnt);
	if (event_ts != prev_ts) {
		event_ts2 =
			aq_nic->aq_hw_ops->hw_ptp_gpio_get_event(aq_nic->aq_hw,
								 clk_sel,
								 cnt);
		if (event_ts != event_ts2) {
			event_ts = event_ts2;
			event_ts2 = aq_nic->aq_hw_ops->hw_ptp_gpio_get_event(
						aq_nic->aq_hw, clk_sel, cnt);

			if (event_ts != event_ts2) {
				netdev_err(aq_nic->ndev,
					   "%s: Unable to get correct GPIO TS",
					   __func__);
				event_ts = 0;
			}
		}

		*new_ts = event_ts;
		return true;
	}
	return false;
}

bool aq_ptp_ts_valid(struct aq_ptp_pid *aq_pid, u64 diff)
{
	/* check we get valid TS, let's use simple check: if difference of
	 * ts_diff and expected period more than half of expected period it
	 * means we've got invalid TS
	 */
	return abs((int64_t)diff - aq_pid->ext_sync_period) <
	       div_u64(aq_pid->ext_sync_period, 3);
}

static void aq_ptp_pid_reset(struct aq_ptp_pid *aq_pid)
{
	memset(aq_pid->delta, 0, sizeof(aq_pid->delta));
	memset(aq_pid->adjust, 0, sizeof(aq_pid->adjust));
	aq_pid->first_diff = true;
}

static int aq_ptp_pid(struct aq_ptp_s *aq_ptp, u64 ts_diff)
{
	s64 p, integral, diff;
	struct aq_ptp_pid *aq_pid = &aq_ptp->pid;

	if (aq_pid->first_diff) {
		aq_pid->first_diff = false;
		return 0;
	}

	if (!aq_ptp_ts_valid(aq_pid, ts_diff)) {
		netdev_err(aq_ptp->aq_nic->ndev,
			   "Invalid TS got, reset synchronization"
			   " algorithm: TS diff: %llu,"
			   " expected: about %llu",
			   ts_diff, aq_pid->ext_sync_period);
		aq_ptp_pid_reset(aq_pid);
		aq_ptp_adjfreq(&aq_ptp->ptp_info, 0);
		return 0;
	}
	aq_pid->delta[0] += ts_diff;
	aq_pid->delta[0] -= aq_pid->ext_sync_period;

	p = PTP_MULT_COEF_P * aq_pid->multiplier *
		(aq_pid->delta[0] - aq_pid->delta[1]);
	integral = PTP_MULT_COEF_I * aq_pid->multiplier * aq_pid->delta[1];
	diff = PTP_MULT_COEF_D * aq_pid->multiplier *
		(aq_pid->delta[0] - 2 * aq_pid->delta[1] +
		aq_pid->delta[2]);

	aq_pr_verbose(aq_ptp->aq_nic, AQ_MSG_PTP,
		   "p = %lld, integral = %lld, diff = %lld",
		   div_s64(p, mul_u32_u32(PTP_DIV_COEF, aq_pid->divider)),
		   div_s64(integral, mul_u32_u32(PTP_DIV_COEF,
						 aq_pid->divider)),
		   div_s64(diff, mul_u32_u32(PTP_DIV_COEF, aq_pid->divider)));

	aq_pid->adjust[0] = div_s64((p + integral + diff),
				     mul_u32_u32(PTP_DIV_COEF,
						 aq_pid->divider)) +
				aq_pid->adjust[1];

	aq_pid->adjust[1] = aq_pid->adjust[0];
	aq_pid->delta[2] = aq_pid->delta[1];
	aq_pid->delta[1] = aq_pid->delta[0];
	aq_pr_verbose(aq_ptp->aq_nic, AQ_MSG_PTP, "delta = %lld, adjust = %lld",
		   aq_pid->delta[0], aq_pid->adjust[0]);

	/* Apply adjust in case if current delta more than 20 or
	 * changing of delta more than 20 (speed of delta
	 * changing)
	 */
	if (abs(aq_pid->delta[0]) > ACCURACY ||
		abs(aq_pid->delta[1] - aq_pid->delta[2]) > ACCURACY)
		aq_ptp_adjfreq(&aq_ptp->ptp_info,
				-aq_pid->adjust[0]);

	return 0;
}

/* Check whether sync1588 pin was triggered, and set stored new PTP time */
static int aq_ptp_check_ext_gpio_event(struct aq_ptp_s *aq_ptp)
{
	struct ptp_clock_info *clock_info = &aq_ptp->ptp_info;
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	int repeat_event = 0;
	int n_pin;

	for (n_pin = 0; n_pin < aq_ptp->ptp_info.n_pins; n_pin++) {
		struct ptp_pin_desc *pin_desc =
			&aq_ptp->ptp_info.pin_config[n_pin];

		if (pin_desc->func == PTP_PF_EXTTS) {
			enum ptp_extts_action action = pin_desc->rsv[2];
			u64 prev_ts = ((uint64_t *)pin_desc->rsv)[0];
			u64 ts = prev_ts;
			u32 cnt = 0;

			repeat_event = 1;
			/* Sync1588 pin was triggered */
			if (aq_ptp_event_ts_updated(aq_ptp,
						    aq_ptp->ptp_clock_sel,
						    prev_ts, &ts, &cnt)) {
				u64 ts_diff = ts - prev_ts;

				aq_pr_verbose(aq_nic, AQ_MSG_PTP,
					   "%s: pin %d with act %x triggered TS: %llu, prev TS %llu, diff %llu",
					   __func__, n_pin, action,
					   ts, prev_ts, ts_diff);

				switch (action) {
				case ptp_extts_timesync: {
					unsigned long flags;

					spin_lock_irqsave(&aq_ptp->ptp_lock,
							  flags);
					aq_nic->aq_hw_ops->hw_set_sys_clock(
						aq_nic->aq_hw,
						aq_ptp->sync_time_value,
						ts);
					spin_unlock_irqrestore(
							&aq_ptp->ptp_lock,
							flags);

					if (aq_ptp->extts_pin_enabled)
						action = ptp_extts_user;
					else
						action = ptp_extts_disabled;

					repeat_event = 0;
				}
				break;
				case ptp_extts_freqsync:
					if (aq_ptp_pid(aq_ptp, ts_diff))
						repeat_event = 0;
					break;
				default:
					break;
				}

				if (aq_ptp->extts_pin_enabled) {
					struct ptp_clock_event ptp_event;
					u64 time = 0;

					aq_nic->aq_hw_ops->hw_ts_to_sys_clock(
							      aq_nic->aq_hw,
							      ts, &time);

					ptp_event.type = PTP_CLOCK_EXTTS;
					ptp_event.index =
						aq_ptp->a2_ptp ?
						n_pin : clock_info->n_pins - 1;
					ptp_event.timestamp = time;
					ptp_clock_event(aq_ptp->ptp_clock,
						&ptp_event);
				}

				((uint64_t *)pin_desc->rsv)[0] = ts;
				pin_desc->rsv[2] = action;
			}
		}
	}

	return repeat_event;
}

/* PTP external GPIO nanoseconds count */
static void aq_ptp_poll_sync_work_cb(struct work_struct *w)
{
	struct delayed_work *dw = to_delayed_work(w);
	struct aq_ptp_s *aq_ptp = container_of(dw, struct aq_ptp_s, poll_sync);

	if (aq_ptp_check_ext_gpio_event(aq_ptp)) {
		unsigned long timeout = msecs_to_jiffies(
						aq_ptp->poll_timeout_ms);

		schedule_delayed_work(&aq_ptp->poll_sync, timeout);
	}
}

static int aq_ptp_hw_pin_conf(struct aq_nic_s *aq_nic, u32 pin_index,
			      u64 start, u64 period)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	aq_pr_verbose(aq_nic, AQ_MSG_PTP,
		   "%sable GPIO %d pulsing, start time %llu, period %u\n",
		   period ? "En" : "Dis", pin_index, start, (u32)period);

	/* Notify hardware of request to being sending pulses.
	 * If period is ZERO then pulsen is disabled.
	 */
	mutex_lock(&aq_nic->fwreq_mutex);
	aq_nic->aq_hw_ops->hw_gpio_pulse(aq_nic->aq_hw, pin_index,
					 aq_ptp->ptp_clock_sel, start,
					 (u32)period, aq_ptp_gpio_hightime);
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
	u32 n_pin = rq->perout.index;
	u64 start, period;

	aq_pr_verbose(aq_nic, AQ_MSG_PTP,
		      "n_pin =  %d t->sec = %lld t->nsec = %d enable = %d",
		      n_pin, t->sec, t->nsec, on);
	/* verify the request channel is there */
	if (n_pin >= ptp->n_per_out)
		return -EINVAL;

	if (aq_ptp->ptp_info.pin_config[n_pin].func != PTP_PF_PEROUT)
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

	aq_ptp->ptp_info.pin_config[n_pin].rsv[2] = on ? ptp_perout_enabled :
	                                            ptp_perout_disabled;

	aq_ptp_hw_pin_conf(aq_nic, aq_ptp->ptp_info.pin_config[n_pin].rsv[3],
			   start, period);

	return 0;
}

static int aq_ptp_pps_pin_configure(struct ptp_clock_info *ptp, int on)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u64 start, period;
	u32 rest = 0;
	u32 n_pin;

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "PPS pin enable = %d\n", on);
	for (n_pin = 0; n_pin < ptp->n_per_out; n_pin++) {
		if (aq_ptp->ptp_info.pin_config[n_pin].func == PTP_PF_PEROUT)
			break;
	}
	/* verify the request channel is there */
	if (n_pin >= ptp->n_per_out)
		return -EINVAL;

	aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &start);
	div_u64_rem(start, NSEC_PER_SEC, &rest);
	period = on ? NSEC_PER_SEC : 0; /* PPS - pulse per second */
	start = on ? start - rest + NSEC_PER_SEC *
		(rest > 990000000LL ? 2 : 1) : 0;

	aq_ptp->ptp_info.pin_config[n_pin].rsv[2] = on ? ptp_perout_pps :
	                                            ptp_perout_disabled;

	aq_ptp_hw_pin_conf(aq_nic, aq_ptp->ptp_info.pin_config[n_pin].rsv[3],
			   start, period);

	return 0;
}

static int aq_ptp_extts_pin_configure(struct ptp_clock_info *ptp,
				      u32 n_pin, enum ptp_extts_action action)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u32 on = (action != ptp_extts_disabled) || aq_ptp->extts_pin_enabled;

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "n_pin = %d action = %d\n", n_pin, action);
	if (!aq_ptp->ptp_info.n_ext_ts ||
		n_pin >= (aq_ptp->ptp_info.n_ext_ts +
			aq_ptp->ptp_info.n_per_out))
		return -EINVAL;

	if (aq_ptp->ptp_info.pin_config[n_pin].func != PTP_PF_EXTTS) {
		netdev_err(aq_nic->ndev, "Pin has invalid function %d instead of %d\n",
			   aq_ptp->ptp_info.pin_config[n_pin].func,
			   PTP_PF_EXTTS);
		return -EINVAL;
	}

	if (aq_ptp->a1_ptp) {
		cancel_delayed_work_sync(&aq_ptp->poll_sync);
	} else {
		if (aq_nic->aq_hw_ops->hw_ext_interrupr_en) {
			aq_nic->aq_hw_ops->hw_ext_interrupr_en(aq_nic->aq_hw,
					on, AQ_HW_PTP_EXT_INT_GPIO0 << n_pin);
		}
	}

	if (action == ptp_extts_disabled && aq_ptp->extts_pin_enabled) {
		action = ptp_extts_user;
		aq_ptp->ptp_info.pin_config[n_pin].rsv[2] = action;
	} else if (action != ptp_extts_user)
		aq_ptp->ptp_info.pin_config[n_pin].rsv[2] = action;
	else if (aq_ptp->ptp_info.pin_config[n_pin].rsv[2] == ptp_extts_disabled)
		aq_ptp->ptp_info.pin_config[n_pin].rsv[2] = action;

	((uint64_t *)aq_ptp->ptp_info.pin_config[n_pin].rsv)[0] =
		aq_nic->aq_hw_ops->hw_ptp_gpio_get_event(aq_nic->aq_hw,
					aq_ptp->ptp_clock_sel, NULL);

	netdev_info(aq_nic->ndev, "GPIO %d input event: %s.\n", n_pin,
		action == ptp_extts_disabled ? "disabled" :
		action == ptp_extts_user ? "requested" :
		action == ptp_extts_timesync ? "time sync" :
		action == ptp_extts_freqsync ? "freq sync" : "unknown");

	aq_nic->aq_hw_ops->hw_extts_gpio_enable(aq_nic->aq_hw,
				aq_ptp->ptp_info.pin_config[n_pin].rsv[3],
				aq_ptp->ptp_clock_sel, on);

	if (aq_ptp->a1_ptp && on && aq_nic->aq_hw->aq_link_status.mbps) {
		if (action != ptp_extts_freqsync)
			aq_ptp->poll_timeout_ms = POLL_SYNC_TIMER_MS;

		/* Here should be request interrupt from firmware */
		schedule_delayed_work(&aq_ptp->poll_sync,
				msecs_to_jiffies(aq_ptp->poll_timeout_ms));
	}

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
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);
	int pin;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		pin = ptp_find_pin(aq_ptp->ptp_clock, PTP_PF_EXTTS,
				   rq->extts.index);
		if (pin < 0) {
			netdev_err(aq_ptp->aq_nic->ndev, "There is no EXTTS pin configured");
			return -EINVAL;
		}
		aq_ptp->extts_pin_enabled = !!on;
		return aq_ptp_extts_pin_configure(ptp, pin,
				on ? ptp_extts_user :
				     aq_ptp->ptp_info.pin_config[pin].rsv[2]);
	case PTP_CLK_REQ_PEROUT:
		return aq_ptp_perout_pin_configure(ptp, rq, on);
	case PTP_CLK_REQ_PPS:
		return aq_ptp_pps_pin_configure(ptp, on);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

/* Store new PTP time and wait until gpio pin triggered */
int aq_ptp_configure_ext_gpio(struct net_device *ndev,
			      struct aq_ptp_ext_gpio_event *ext_gpio_event)
{
	enum ptp_extts_action action = ptp_extts_disabled;
	u32 n_pin = ext_gpio_event->gpio_index;
	struct aq_ptp_s *aq_ptp = NULL;
	struct aq_nic_s *aq_nic = NULL;
	int err = 0;

	if (!ndev)
		return -EINVAL;

	if (ndev->ethtool_ops != &aq_ethtool_ops)
		return -EINVAL;

	aq_nic = netdev_priv(ndev);
	if (!aq_nic)
		return -EINVAL;

	aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp) {
		err = -EOPNOTSUPP;
		goto err_exit;
	}

	if (!aq_ptp->ptp_info.n_ext_ts ||
		n_pin >= (aq_ptp->ptp_info.n_ext_ts +
			aq_ptp->ptp_info.n_per_out)) {
		netdev_info(aq_nic->ndev,
			"Not supported, selected EXT TS pin was not advertised");
		err = -EOPNOTSUPP;
		goto err_exit;
	}

	if (aq_ptp->a1_ptp) {
		//Not required if FW supports
		cancel_delayed_work_sync(&aq_ptp->poll_sync);
		aq_ptp->poll_timeout_ms = POLL_SYNC_TIMER_MS;
	}

	switch (ext_gpio_event->action) {
	case aq_sync_cntr_set:
		netdev_info(aq_nic->ndev, "Enable sync time on event:%llu",
			    ext_gpio_event->time_ns);
		action = ptp_extts_timesync;
		aq_ptp->sync_time_value = ext_gpio_event->time_ns;
		break;
	case 0:
		break;
	default:
		err = -EOPNOTSUPP;
		goto err_exit;
	}

	if (ext_gpio_event->clock_sync_en) {
		if (ext_gpio_event->sync_pulse_ms < 50 ||
		    ext_gpio_event->sync_pulse_ms > MSEC_PER_SEC) {
			netdev_err(aq_nic->ndev,
				   "Sync pulse ms should not be equal less"
				   " than 50ms or higher than 1s");
			err = -EINVAL;
			goto err_exit;
		}

		netdev_info(aq_nic->ndev,
			    "Enable sync clock with ext signal with period: %u",
			    ext_gpio_event->sync_pulse_ms);
		action = ptp_extts_freqsync;
		aq_ptp->pid.ext_sync_period =
			(uint64_t)ext_gpio_event->sync_pulse_ms *
				NSEC_PER_MSEC;

		aq_ptp->pid.multiplier = div_u64(mul_u32_u32(NSEC_PER_SEC,
							     PTP_DIV_RATIO),
						 aq_ptp->pid.ext_sync_period);

		aq_ptp->pid.divider = PTP_DIV_RATIO;

		/* If we need only clock sync poll TS at least
		 * 3 times per period
		 */
		aq_ptp->poll_timeout_ms = div_u64(ext_gpio_event->sync_pulse_ms,
						  3);
	}

	if (action == ptp_extts_disabled) {
		netdev_info(aq_nic->ndev, "Disable sync time/freq on event");
		aq_ptp_pid_reset(&aq_ptp->pid);
	}

	err = aq_ptp_extts_pin_configure(&aq_ptp->ptp_info,
					 ext_gpio_event->gpio_index,
					 action);

err_exit:
	return err;
}

/* aq_ptp_verify
 * @ptp: the ptp clock structure
 * @pin: index of the pin in question
 * @func: the desired function to use
 * @chan: the function channel index to use
 */
static int aq_ptp_verify(struct ptp_clock_info *ptp, unsigned int n_pin,
			 enum ptp_pin_function func, unsigned int chan)
{
	struct aq_ptp_s *aq_ptp = container_of(ptp, struct aq_ptp_s, ptp_info);

	aq_pr_verbose(aq_ptp->aq_nic, AQ_MSG_PTP, "n_pin = %d func = %d chan = %d\n",
			n_pin, func, chan);
	/* verify the requested pin is there */
	if (n_pin >= ptp->n_pins)
		return -EINVAL;

	/* we want to keep the functions locked as well */
	switch (func) {
	case PTP_PF_NONE:
		break;
	case PTP_PF_EXTTS:
		if (aq_ptp->a1_ptp && n_pin < ptp->n_per_out) {
			/* A1: Only SYNC1588 may be PTP input,
			 * A2 all GPIO may be input
			 */
			netdev_err(aq_ptp->aq_nic->ndev, "Only SYNC1588 may be PTP input");
			return -EINVAL;
		}
		break;
	case PTP_PF_PEROUT:
		/* A1: Only main GPIO may be PTP output */
		if ((aq_ptp->a1_ptp && n_pin >= ptp->n_per_out) ||
		   (n_pin > ptp->n_per_out)) {
			netdev_err(aq_ptp->aq_nic->ndev, "Only main GPIO may be PTP output");
			return -EINVAL;
		}

		/* ANT_A0 ASIC: Only GPIO1 or GPIO3 may be PTP output */
		if (aq_ptp->a2_ptp &&
		    !(ATL_HW_IS_CHIP_FEATURE(aq_ptp->aq_nic->aq_hw, FPGA)) &&
		    !(aq_ptp->ptp_info.pin_config[n_pin].rsv[3] == 1) &&
		    !(aq_ptp->ptp_info.pin_config[n_pin].rsv[3] == 3)) {
			netdev_err(aq_ptp->aq_nic->ndev, "Only GPIO1 or GPIO3 may be PTP output");
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
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

static int aq_ptp_dpath_enable(struct aq_ptp_s *aq_ptp,
			       int enable_flags, u16 rx_queue)
{
	int err = 0, i = 0;
	struct ethtool_rxnfc cmd = { 0 };
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd.fs;
	const struct aq_hw_ops *hw_ops = aq_nic->aq_hw_ops;
	int flt_idx = 0;

	netdev_dbg(aq_nic->ndev,
		   "%sable ptp filters: %x.\n",
		   enable_flags ? "En" : "Dis", enable_flags);

	if (enable_flags) {
		if (enable_flags & (AQ_HW_PTP_L4_ENABLE)) {
			if (aq_ptp->a1_ptp) {
				fsp->ring_cookie = rx_queue;
				fsp->flow_type = UDP_V4_FLOW;
				fsp->h_u.udp_ip4_spec.pdst =
					cpu_to_be16(PTP_EV_PORT);
				fsp->m_u.udp_ip4_spec.pdst =
					cpu_to_be16(0xffff);
				err = aq_set_data_fl3l4(fsp,
					&aq_ptp->udp_filter[flt_idx],
					aq_ptp->udp_filter[flt_idx].location,
					true);
				if (!err) {
					netdev_info(aq_nic->ndev,
						"Set UDPv4, location: %x\n",
						aq_ptp->udp_filter[flt_idx]
							.location);
					flt_idx++;
				}
			} else {
				fsp->ring_cookie = rx_queue;
				fsp->flow_type = UDP_V4_FLOW;
				fsp->h_u.udp_ip4_spec.psrc = 0;
				fsp->m_u.udp_ip4_spec.psrc = 0;
				fsp->h_u.udp_ip4_spec.pdst =
					cpu_to_be16(PTP_EV_PORT);
				fsp->m_u.udp_ip4_spec.pdst =
					cpu_to_be16(0xffff);
				fsp->h_u.udp_ip4_spec.ip4dst =
					cpu_to_be32(PTP_IPV4_MC_ADDR1);
				fsp->m_u.udp_ip4_spec.ip4dst =
					cpu_to_be32(0xffffffff);
				err = aq_set_data_fl3l4(fsp,
					&aq_ptp->udp_filter[flt_idx],
					aq_ptp->udp_filter[flt_idx].location,
					true);
				if (!err) {
					netdev_info(aq_nic->ndev,
						"UDPv4 filter prepared. Loc: %x\n",
						aq_ptp->udp_filter[flt_idx]
							.location);
					flt_idx++;
				}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0) ||\
	RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 3)
				memset(fsp, 0, sizeof(*fsp));
				fsp->ring_cookie = rx_queue;
				fsp->flow_type = UDP_V6_FLOW;
				fsp->h_u.udp_ip6_spec.psrc = 0;
				fsp->m_u.udp_ip6_spec.psrc = 0;
				fsp->h_u.udp_ip6_spec.pdst =
					cpu_to_be16(PTP_EV_PORT);
				fsp->m_u.udp_ip6_spec.pdst =
					cpu_to_be16(0xffff);
				fsp->h_u.udp_ip6_spec.ip6dst[0] =
					cpu_to_be32(PTP_IPV6_MC_ADDR20 << 16);
				fsp->m_u.udp_ip6_spec.ip6dst[0] =
					cpu_to_be32(0xffff0000);
				fsp->h_u.udp_ip6_spec.ip6dst[3] =
					cpu_to_be32(PTP_IPV6_MC_ADDR24);
				fsp->m_u.udp_ip6_spec.ip6dst[3] =
					cpu_to_be32(0x0000ffff);
				err = aq_set_data_fl3l4(fsp,
					&aq_ptp->udp_filter[flt_idx],
					aq_ptp->udp_filter[flt_idx].location,
					true);
				if (!err) {
					netdev_info(aq_nic->ndev,
						"UDPv6 filter prepared. Loc: %x\n",
						aq_ptp->udp_filter[flt_idx]
							.location);
					flt_idx++;
				}
				memset(fsp, 0, sizeof(*fsp));
				fsp->ring_cookie = rx_queue;
				fsp->flow_type = UDP_V6_FLOW;
				fsp->h_u.udp_ip6_spec.psrc = 0;
				fsp->m_u.udp_ip6_spec.psrc = 0;
				fsp->h_u.udp_ip6_spec.pdst =
					cpu_to_be16(PTP_EV_PORT);
				fsp->m_u.udp_ip6_spec.pdst =
					cpu_to_be16(0xffff);
				fsp->h_u.udp_ip6_spec.ip6dst[0] =
					cpu_to_be32(PTP_IPV6_MC_ADDR10 << 16);
				fsp->m_u.udp_ip6_spec.ip6dst[0] =
					cpu_to_be32(0xffff0000);
				fsp->h_u.udp_ip6_spec.ip6dst[3] =
					cpu_to_be32(PTP_IPV6_MC_ADDR14);
				fsp->m_u.udp_ip6_spec.ip6dst[3] =
					cpu_to_be32(0x0000ffff);
				err = aq_set_data_fl3l4(fsp,
					&aq_ptp->udp_filter[flt_idx],
					aq_ptp->udp_filter[flt_idx].location,
					true);
				if (!err) {
					netdev_info(aq_nic->ndev,
						"UDPv6 filter prepared. Loc: %x\n",
						aq_ptp->udp_filter[flt_idx]
							.location);
					flt_idx++;
				}
#endif
				memset(fsp, 0, sizeof(*fsp));
				fsp->ring_cookie = rx_queue;
				fsp->flow_type = UDP_V4_FLOW;
				fsp->h_u.udp_ip4_spec.psrc = 0;
				fsp->m_u.udp_ip4_spec.psrc = 0;
				fsp->h_u.udp_ip4_spec.pdst =
					cpu_to_be16(PTP_EV_PORT);
				fsp->m_u.udp_ip4_spec.pdst =
					cpu_to_be16(0xffff);
				fsp->h_u.udp_ip4_spec.ip4dst =
					cpu_to_be32(PTP_IPV4_MC_ADDR2);
				fsp->m_u.udp_ip4_spec.ip4dst =
					cpu_to_be32(0xffffffff);
				err = aq_set_data_fl3l4(fsp,
					&aq_ptp->udp_filter[flt_idx],
					aq_ptp->udp_filter[flt_idx].location,
					true);
				if (!err) {
					netdev_info(aq_nic->ndev,
						"UDPv4 filter prepared. Loc: %x\n",
						aq_ptp->udp_filter[flt_idx]
							.location);
					flt_idx++;
				}
			}
		}


		if (enable_flags & AQ_HW_PTP_L2_ENABLE) {
			aq_ptp->eth_type_filter.ethertype = ETH_P_1588;
			aq_ptp->eth_type_filter.queue = rx_queue;
		}

		if (hw_ops->hw_filter_l3l4_set) {
			for (i = 0; i < flt_idx; i++) {
				err = hw_ops->hw_filter_l3l4_set(aq_nic->aq_hw,
						&aq_ptp->udp_filter[i]);

				if (!err) {
					netdev_info(aq_nic->ndev,
						"Set UDP filter complete. Location: %x\n",
						aq_ptp->udp_filter[i].location);
				} else {
					netdev_info(aq_nic->ndev, "Set UDP filter failed\n");
					break;
				}
			}
		}

		if (!err && hw_ops->hw_filter_l2_set) {
			err = hw_ops->hw_filter_l2_set(aq_nic->aq_hw,
					&aq_ptp->eth_type_filter);

			if (!err)
				netdev_info(aq_nic->ndev,
					    "Set L2 filter complete. Location: %d\n",
					    aq_ptp->eth_type_filter.location);
		}
	} else {
		/* PTP disabled, clear all UDP/L2 filters */
		for (i = 0; i < PTP_UDP_FILTERS_CNT; i++) {
			aq_ptp->udp_filter[i].cmd &=
				~HW_ATL_RX_ENABLE_FLTR_L3L4;
			if (hw_ops->hw_filter_l3l4_set)
				err = hw_ops->hw_filter_l3l4_set(aq_nic->aq_hw,
						&aq_ptp->udp_filter[i]);
		}

		if (!err && hw_ops->hw_filter_l2_clear)
			err = hw_ops->hw_filter_l2_clear(aq_nic->aq_hw,
						&aq_ptp->eth_type_filter);
	}

	return err;
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

static int aq_ptp_parse_rx_filters(enum hwtstamp_rx_filters rx_filter)
{
	unsigned int ptp_en_flags = AQ_HW_PTP_DISABLE;

	switch (rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		break;
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
		ptp_en_flags = AQ_HW_PTP_L2_ENABLE;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		ptp_en_flags = AQ_HW_PTP_L4_ENABLE;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		ptp_en_flags = AQ_HW_PTP_L4_ENABLE | AQ_HW_PTP_L2_ENABLE;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_ALL:
		/* fall through */
	default:
		return -ERANGE;
	}
	return ptp_en_flags;
}

int aq_ptp_hwtstamp_config_set(struct aq_ptp_s *aq_ptp,
			       struct hwtstamp_config *config)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	int err = 0;
	int ptp_en_flags = aq_ptp_parse_rx_filters(config->rx_filter);

	aq_pr_verbose(aq_nic, AQ_MSG_PTP, "ptp_en_flags = %d\n", ptp_en_flags);
	if (ptp_en_flags == -ERANGE) {
		config->rx_filter = HWTSTAMP_FILTER_NONE;
		return -ERANGE;
	}

	if (aq_ptp->hwtstamp_config.rx_filter != config->rx_filter)
		err = aq_ptp_dpath_enable(aq_ptp,
					  ptp_en_flags,
					  aq_ptp->ptp_rx.idx);

	if (ptp_en_flags != AQ_HW_PTP_DISABLE)
		aq_utils_obj_set(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP);
	else
		aq_utils_obj_clear(&aq_nic->flags, AQ_NIC_PTP_DPATH_UP);

	if (err)
		return -EREMOTEIO;

	aq_ptp->hwtstamp_config = *config;

	return 0;
}

bool aq_ptp_ring(struct aq_ring_s *ring)
{
	struct aq_nic_s *aq_nic = ring->aq_nic;
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

	if (aq_ptp->a1_ptp) {
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
		napi_complete_done(napi, work_done);
		aq_nic->aq_hw_ops->hw_irq_enable(aq_nic->aq_hw,
					BIT_ULL(aq_ptp->ptp_ring_param.vec_idx));
	}

err_exit:
	return work_done;
}

static irqreturn_t aq_ext_ptp_isr(int irq, void *private)
{
	struct aq_ptp_s *aq_ptp = private;
	const struct aq_hw_ops *hw_ops;
	int err = 0;

	if (!aq_ptp) {
		err = -EINVAL;
		goto err_exit;
	}

	hw_ops = aq_ptp->aq_nic->aq_hw_ops;

	aq_ptp_check_ext_gpio_event(aq_ptp);

	hw_ops->hw_irq_enable(aq_ptp->aq_nic->aq_hw,
			      BIT_ULL(aq_ptp->idx_gpio_vector));

err_exit:
	return err >= 0 ? IRQ_HANDLED : IRQ_NONE;
}

static irqreturn_t aq_ptp_isr(int irq, void *private)
{
	struct aq_ptp_s *aq_ptp = private;
	int err = 0;

	if (!aq_ptp) {
		err = -EINVAL;
		goto err_exit;
	}

	u64_stats_update_begin(&aq_ptp->ptp_rx.stats.rx.syncp);
	aq_ptp->ptp_rx.stats.rx.irqs++;
	u64_stats_update_end(&aq_ptp->ptp_rx.stats.rx.syncp);
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
			u64_stats_update_begin(&ring->stats.tx.syncp);
			++ring->stats.tx.packets;
			ring->stats.tx.bytes += skb->len;
			u64_stats_update_end(&ring->stats.tx.syncp);
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
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	struct pci_dev *pdev = aq_nic->pdev;
	int err = 0;

	if (!aq_ptp)
		return 0;

	if (!pdev->msix_enabled && !pdev->msi_enabled)
		return -EINVAL;

	err = request_irq(pci_irq_vector(pdev,
					 aq_ptp->idx_ptp_vector),
			  aq_ptp_isr, 0, aq_nic->ndev->name, aq_ptp);

	if (!err)
		err = request_irq(pci_irq_vector(pdev,
						 aq_ptp->idx_gpio_vector),
				  aq_ext_ptp_isr, 0, aq_nic->ndev->name, aq_ptp);

	return err;
}

void aq_ptp_irq_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	struct pci_dev *pdev = aq_nic->pdev;

	if (!aq_ptp)
		return;

	free_irq(pci_irq_vector(pdev, aq_ptp->idx_ptp_vector), aq_ptp);
	free_irq(pci_irq_vector(pdev, aq_ptp->idx_gpio_vector), aq_ptp);
}

int aq_ptp_ring_init(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int err = 0;

	if (!aq_ptp)
		return 0;

	err = aq_ring_init(&aq_ptp->ptp_tx, ATL_RING_TX);
	if (err < 0)
		goto err_exit;
	err = aq_nic->aq_hw_ops->hw_ring_tx_init(aq_nic->aq_hw,
						 &aq_ptp->ptp_tx,
						 &aq_ptp->ptp_ring_param);
	if (err < 0)
		goto err_exit;

	err = aq_ring_init(&aq_ptp->ptp_rx, ATL_RING_RX);
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

	if (aq_ptp->a2_ptp)
		return 0;

	err = aq_ring_init(&aq_ptp->hwts_rx, ATL_RING_RX);
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

	if (aq_ptp->a1_ptp) {
		err = aq_nic->aq_hw_ops->hw_ring_rx_start(aq_nic->aq_hw,
							  &aq_ptp->hwts_rx);
		if (err < 0)
			goto err_exit;
	}

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

	if (aq_ptp->a1_ptp) {
		aq_nic->aq_hw_ops->hw_ring_rx_stop(aq_nic->aq_hw,
						   &aq_ptp->hwts_rx);
	}

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

int aq_ptp_ring_alloc(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	unsigned int tx_ring_idx, rx_ring_idx;
	struct aq_ring_s *hwts;
	struct aq_ring_s *ring;
	int err;

	if (!aq_ptp)
		return 0;

	tx_ring_idx = aq_ptp_ring_idx(aq_nic->aq_nic_cfg.tc_mode);

	ring = aq_ring_tx_alloc(&aq_ptp->ptp_tx, aq_nic,
				tx_ring_idx, &aq_nic->aq_nic_cfg);
	if (!ring) {
		err = -ENOMEM;
		goto err_exit;
	}

	rx_ring_idx = aq_ptp_ring_idx(aq_nic->aq_nic_cfg.tc_mode);

	ring = aq_ring_rx_alloc(&aq_ptp->ptp_rx, aq_nic,
				rx_ring_idx, &aq_nic->aq_nic_cfg);
	if (!ring) {
		err = -ENOMEM;
		goto err_exit_ptp_tx;
	}

	if (aq_ptp->a1_ptp) {
		hwts = aq_ring_hwts_rx_alloc(&aq_ptp->hwts_rx, aq_nic,
					     PTP_HWST_RING_IDX,
					     aq_nic->aq_nic_cfg.rxds,
					     aq_nic->aq_nic_cfg.aq_hw_caps->rxd_size);
		if (!hwts) {
			err = -ENOMEM;
			goto err_exit_ptp_rx;
		}
	}

	err = aq_ptp_skb_ring_init(&aq_ptp->skb_ring, aq_nic->aq_nic_cfg.rxds);
	if (err != 0) {
		err = -ENOMEM;
		goto err_exit_hwts_rx;
	}

	aq_ptp->ptp_ring_param.vec_idx = aq_ptp->idx_ptp_vector;
	aq_ptp->ptp_ring_param.cpu = aq_ptp->ptp_ring_param.vec_idx +
			aq_nic_get_cfg(aq_nic)->aq_rss.base_cpu_number;
	cpumask_set_cpu(aq_ptp->ptp_ring_param.cpu,
			&aq_ptp->ptp_ring_param.affinity_mask);

	return 0;

err_exit_hwts_rx:
	if (aq_ptp->a1_ptp)
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
	if (aq_ptp->a1_ptp)
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
	/* enable periodic outputs */
	.n_per_out	= 0,
	.enable		= aq_ptp_gpio_feature_enable,
	/* enable clock pins */
	.n_pins		= 0,
	.verify		= aq_ptp_verify,
	.pin_config	= NULL,
};

#define ptp_offset_init(__aq_ptp, __idx, __mbps, __egress, __ingress)   do { \
		__aq_ptp->ptp_offset[__idx].mbps = (__mbps); \
		__aq_ptp->ptp_offset[__idx].egress = (__egress); \
		__aq_ptp->ptp_offset[__idx].ingress = (__ingress); } \
		while (0)

static void aq_ptp_offset_init_from_fw(struct aq_ptp_s *aq_ptp,
				       const struct hw_atl_ptp_offset *offsets)
{
	int i;

	/* Load offsets for PTP */
	for (i = 0; i < ARRAY_SIZE(aq_ptp->ptp_offset); i++) {
		switch (i) {
		/* 100M */
		case ptp_offset_idx_100:
			ptp_offset_init(aq_ptp, i, 100,
					offsets->egress_100,
					offsets->ingress_100);
			break;
		/* 1G */
		case ptp_offset_idx_1000:
			ptp_offset_init(aq_ptp, i, 1000,
					offsets->egress_1000,
					offsets->ingress_1000);
			break;
		/* 2.5G */
		case ptp_offset_idx_2500:
			ptp_offset_init(aq_ptp, i, 2500,
					offsets->egress_2500,
					offsets->ingress_2500);
			break;
		/* 5G */
		case ptp_offset_idx_5000:
			ptp_offset_init(aq_ptp, i, 5000,
					offsets->egress_5000,
					offsets->ingress_5000);
			break;
		/* 10G */
		case ptp_offset_idx_10000:
			ptp_offset_init(aq_ptp, i, 10000,
					offsets->egress_10000,
					offsets->ingress_10000);
			break;
		}
	}
}

static void aq_ptp_offset_init_from_params(struct aq_ptp_s *aq_ptp, int force)
{
	if (force || aq_ptp_offset_100)
		ptp_offset_init(aq_ptp, ptp_offset_idx_100, 100,
				(aq_ptp_offset_100 >> 16) & 0xffff,
				aq_ptp_offset_100 & 0xffff);
	if (force || aq_ptp_offset_1000)
		ptp_offset_init(aq_ptp, ptp_offset_idx_1000, 1000,
				(aq_ptp_offset_1000 >> 16) & 0xffff,
				aq_ptp_offset_1000 & 0xffff);
	if (force || aq_ptp_offset_2500)
		ptp_offset_init(aq_ptp, ptp_offset_idx_2500, 2500,
				(aq_ptp_offset_2500 >> 16) & 0xffff,
				aq_ptp_offset_2500 & 0xffff);
	if (force || aq_ptp_offset_5000)
		ptp_offset_init(aq_ptp, ptp_offset_idx_5000, 5000,
				(aq_ptp_offset_5000 >> 16) & 0xffff,
				aq_ptp_offset_5000 & 0xffff);
	if (force || aq_ptp_offset_10000)
		ptp_offset_init(aq_ptp, ptp_offset_idx_10000, 10000,
				(aq_ptp_offset_10000 >> 16) & 0xffff,
				aq_ptp_offset_10000 & 0xffff);
}

static void aq_ptp_offset_init(struct aq_ptp_s *aq_ptp,
			       const struct hw_atl_ptp_offset *offsets)
{
	memset(aq_ptp->ptp_offset, 0, sizeof(aq_ptp->ptp_offset));

	if (aq_ptp_offset_forced) {
		aq_ptp_offset_init_from_params(aq_ptp, 1);
	} else {
		aq_ptp_offset_init_from_fw(aq_ptp, offsets);
		aq_ptp_offset_init_from_params(aq_ptp, 0);
	}
}

static void aq_ptp_gpio_init(struct aq_ptp_s *aq_ptp,
	enum gpio_pin_function gpio_pin[MAX_PTP_GPIO_COUNT],
	int sync1588_input)
{
	struct ptp_pin_desc pin_desc[MAX_PTP_GPIO_COUNT];
	u32 ncount = 0;
	u32 i;

	memset(pin_desc, 0, sizeof(pin_desc));
	for (i = 0; i < MAX_PTP_GPIO_COUNT; i++) {
		if (gpio_pin[i] == (GPIO_PIN_FUNCTION_PTP0 + ncount)) {
			snprintf(pin_desc[ncount].name, sizeof(pin_desc[ncount].name),
				 "AQ_GPIO%d_%s", i, aq_ptp->a1_ptp ? "OUT" :
					(i & 1) ? "INOUT" : "IN");
			pin_desc[ncount].index = ncount;
			pin_desc[ncount].chan = 0;
			pin_desc[ncount].rsv[3] = i;
			pin_desc[ncount++].func = PTP_PF_NONE;
		}
	}
	aq_ptp->ptp_info.n_per_out = ncount;

	if (aq_ptp->aq_nic->aq_hw_ops->hw_extts_gpio_enable &&
		aq_ptp->aq_nic->aq_hw_ops->hw_ptp_gpio_get_event) {

		//AQC107 has single input SYNC1588
		if (sync1588_input && ncount < MAX_PTP_GPIO_COUNT) {
			snprintf(pin_desc[ncount].name, sizeof(pin_desc[ncount].name),
				"AQ_GPIO%d_SYNC1588_IN", ncount);
			pin_desc[ncount].index = ncount;
			pin_desc[ncount].func = PTP_PF_NONE;
			pin_desc[ncount].rsv[3] = i;
			pin_desc[ncount++].chan = 0;
		}

		/* AQC113 has two indepent counters doesn't make sence
		 * to use more than 2 channels
		 */
		aq_ptp->ptp_info.n_ext_ts =
			aq_ptp->a2_ptp ? (ncount >= 2 ? 2 : ncount) :
				!!sync1588_input;
	}

	aq_ptp->ptp_info.n_pins = ncount;

	if (!aq_ptp->ptp_info.n_pins)
		return;

	aq_ptp->ptp_info.pin_config = kcalloc(aq_ptp->ptp_info.n_pins,
					      sizeof(struct ptp_pin_desc),
					      GFP_KERNEL);

	if (!aq_ptp->ptp_info.pin_config)
		return;

	memcpy(aq_ptp->ptp_info.pin_config, &pin_desc,
	       sizeof(struct ptp_pin_desc) * aq_ptp->ptp_info.n_pins);
}

void aq_ptp_clock_init(struct aq_nic_s *aq_nic, enum aq_ptp_state state)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	if (aq_ptp->a1_ptp || state == AQ_PTP_FIRST_INIT) {
		struct timespec64 ts;

		ktime_get_real_ts64(&ts);
		aq_ptp_settime(&aq_ptp->ptp_info, &ts);
	}

	if (aq_ptp->a1_ptp) {
		if (state == AQ_PTP_LINK_UP) {
			u32 n_pin = aq_ptp->ptp_info.n_pins - 1;

			if (n_pin < MAX_PTP_GPIO_COUNT &&
				aq_ptp->ptp_info.pin_config[n_pin].func ==
					PTP_PF_EXTTS) {
				aq_ptp_pid_reset(&aq_ptp->pid);
				aq_ptp_extts_pin_configure(&aq_ptp->ptp_info,
					n_pin,
					aq_ptp->ptp_info.pin_config[n_pin]
						.rsv[2]);
			}
		} else {
			cancel_delayed_work_sync(&aq_ptp->poll_sync);
			aq_ptp_pid_reset(&aq_ptp->pid);
		}
	}

	if (!aq_ptp->a1_ptp && state != AQ_PTP_FIRST_INIT) {
		int ptp_en_flags =
			aq_ptp_parse_rx_filters(state == AQ_PTP_LINK_UP ?
				aq_ptp->hwtstamp_config.rx_filter :
					AQ_HW_PTP_DISABLE);
		if (ptp_en_flags != -ERANGE)
			aq_ptp_dpath_enable(aq_ptp,
					    ptp_en_flags,
					    aq_ptp->ptp_rx.idx);
	}
}

static int aq_pps_reconfigure(struct aq_ptp_s *aq_ptp)
{
	struct aq_nic_s *aq_nic = aq_ptp->aq_nic;
	u64 start, period;
	u32 rest;
	int i;

	for (i = 0; i < aq_ptp->ptp_info.n_pins; i++)
		if ((aq_ptp->ptp_info.pin_config[i].func == PTP_PF_PEROUT) &&
		    (aq_ptp->ptp_info.pin_config[i].rsv[2] == ptp_perout_pps)) {
				aq_nic->aq_hw_ops->hw_get_ptp_ts(aq_nic->aq_hw, &start);
				div_u64_rem(start, NSEC_PER_SEC, &rest);
				period = NSEC_PER_SEC;
				start = start - rest + NSEC_PER_SEC * (rest > 990000000LL ? 2 : 1);

				aq_ptp_hw_pin_conf(aq_nic, aq_ptp->ptp_info.pin_config[i].rsv[3],
						start, period);
			}

	return 0;
}

int aq_ptp_init(struct aq_nic_s *aq_nic, unsigned int idx_ptp_vec, unsigned int idx_ext_vec)
{
	bool a1_ptp = ATL_HW_IS_CHIP_FEATURE(aq_nic->aq_hw, ATLANTIC);
	bool a2_ptp = ATL_HW_IS_CHIP_FEATURE(aq_nic->aq_hw, ANTIGUA);
	struct aq_ptp_s *aq_ptp = NULL;
	struct hw_atl_utils_mbox mbox;
	struct ptp_clock *clock;
	int err = 0;
	int i = 0;

	if (!a1_ptp && !a2_ptp)
		goto err_exit;

	/* PTP requires at least 2 free irq vectors for itself */
	if (aq_nic->irqvecs <= AQ_HW_PTP_IRQS) {
		netdev_warn(aq_nic->ndev,
		    "Disabling PTP due to insufficient number of available IRQ vectors.\n");
		goto err_exit;
	}

	if (a1_ptp) {
		hw_atl_utils_mpi_read_stats(aq_nic->aq_hw, &mbox);
		if (!(mbox.info.caps_ex & BIT(CAPS_EX_PHY_PTP_EN)))
			goto err_exit;
	} else {
		memset(&mbox, 0, sizeof(mbox));

		if (a2_ptp) {
			/* 7x7 has only GPIO0 */
			mbox.info.gpio_pin[0] = GPIO_PIN_FUNCTION_NC;
			mbox.info.gpio_pin[1] = GPIO_PIN_FUNCTION_NC;
			/* GPIO 2,3: 12x14 only! */
			mbox.info.gpio_pin[2] = GPIO_PIN_FUNCTION_NC;
			//TODO mbox.info.gpio_pin[3] = GPIO_PIN_FUNCTION_PTP1;

			//DV values
			mbox.info.ptp_offset.ingress_100 = 768;
			mbox.info.ptp_offset.egress_100 = 336;
			mbox.info.ptp_offset.ingress_1000 = 510;
			mbox.info.ptp_offset.egress_1000 = 105;
			mbox.info.ptp_offset.ingress_2500 = 2447;
			mbox.info.ptp_offset.egress_2500 = 634;
			mbox.info.ptp_offset.ingress_5000 = 1426;
			mbox.info.ptp_offset.egress_5000 = 361;
			mbox.info.ptp_offset.ingress_10000 = 997;
			mbox.info.ptp_offset.egress_10000 = 203;
		}
	}

	aq_ptp = kzalloc(sizeof(*aq_ptp), GFP_KERNEL);
	if (!aq_ptp) {
		err = -ENOMEM;
		goto err_exit;
	}

	aq_ptp->aq_nic = aq_nic;
	aq_ptp->a1_ptp = a1_ptp;
	aq_ptp->a2_ptp = a2_ptp;

	spin_lock_init(&aq_ptp->ptp_lock);
	spin_lock_init(&aq_ptp->ptp_ring_lock);

	aq_ptp_offset_init(aq_ptp, &mbox.info.ptp_offset); //TODO offsets for A2
	aq_ptp->ptp_info = aq_ptp_clock;
	aq_ptp_gpio_init(aq_ptp, mbox.info.gpio_pin,
			 a1_ptp ? mbox.info.caps_ex &
				BIT(CAPS_EX_PHY_CTRL_TS_PIN) : 0);

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

	aq_ptp->idx_ptp_vector = idx_ptp_vec;
	aq_ptp->idx_gpio_vector = idx_ext_vec;

	aq_nic->aq_ptp = aq_ptp;

	/* enable ptp counter */
	aq_ptp->ptp_clock_sel = ATL_TSG_CLOCK_SEL_0; //mbox.info.caps_ex.;
	aq_utils_obj_set(&aq_nic->aq_hw->flags, AQ_HW_PTP_AVAILABLE);
	if (a1_ptp) {
		mutex_lock(&aq_nic->fwreq_mutex);
		aq_nic->aq_fw_ops->enable_ptp(aq_nic->aq_hw, 1);
		mutex_unlock(&aq_nic->fwreq_mutex);
	}
	if (a2_ptp)
		aq_nic->aq_hw_ops->enable_ptp(aq_nic->aq_hw, aq_ptp->ptp_clock_sel, 1);

	INIT_DELAYED_WORK(&aq_ptp->poll_sync, &aq_ptp_poll_sync_work_cb);

	aq_ptp->eth_type_filter.location =
		aq_nic_reserve_filter(aq_nic, aq_rx_filter_ethertype);


	for (i = 0; i < PTP_UDP_FILTERS_CNT; i++) {
		aq_ptp->udp_filter[i].location =
			aq_nic_reserve_filter(aq_nic, aq_rx_filter_l3l4);
	}

	aq_ptp_clock_init(aq_nic, AQ_PTP_FIRST_INIT);
	netdev_info(aq_nic->ndev,
		    "Enable PTP Support. %d GPIO(s)\n",
		    aq_ptp->ptp_info.n_pins);

	return 0;

err_exit:
	if (aq_ptp)
		kfree(aq_ptp->ptp_info.pin_config);
	kfree(aq_ptp);
	aq_nic->aq_ptp = NULL;
	return err;
}

/* aq_ptp_stop - close the PTP device
 * @adapter: pointer to adapter struct
 *
 * completely destroy the PTP device, should only be called when the device is
 * being fully closed.
 */
void aq_ptp_unregister(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;

	if (!aq_ptp)
		return;

	if (aq_ptp->ptp_clock) {
		ptp_clock_unregister(aq_ptp->ptp_clock);
		aq_ptp->ptp_clock = NULL;
	}
}

void aq_ptp_free(struct aq_nic_s *aq_nic)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	int i = 0;

	if (!aq_ptp)
		return;

	/* disable ptp */
	if (aq_ptp->a1_ptp) {
		cancel_delayed_work_sync(&aq_ptp->poll_sync);
		mutex_lock(&aq_nic->fwreq_mutex);
		aq_nic->aq_fw_ops->enable_ptp(aq_nic->aq_hw, 0);
		mutex_unlock(&aq_nic->fwreq_mutex);
	}

	if (aq_ptp->a2_ptp)
		aq_nic->aq_hw_ops->enable_ptp(aq_nic->aq_hw,
					      aq_ptp->ptp_clock_sel, 0);

	aq_nic_release_filter(aq_nic, aq_rx_filter_ethertype,
			      aq_ptp->eth_type_filter.location);
	for (i = 0; i < PTP_UDP_FILTERS_CNT; i++)
		aq_nic_release_filter(aq_nic, aq_rx_filter_l3l4,
			      aq_ptp->udp_filter[i].location);

	kfree(aq_ptp->ptp_info.pin_config);
	aq_ptp->ptp_info.pin_config = NULL;

	netif_napi_del(&aq_ptp->napi);
	kfree(aq_ptp);
	aq_utils_obj_clear(&aq_nic->aq_hw->flags, AQ_HW_PTP_AVAILABLE);
	aq_nic->aq_ptp = NULL;
}

struct ptp_clock *aq_ptp_get_ptp_clock(struct aq_ptp_s *aq_ptp)
{
	return aq_ptp->ptp_clock;
}

int aq_ptp_get_ring_cnt(struct aq_nic_s *aq_nic, const enum atl_ring_type ring_type)
{
	if (!aq_nic->aq_ptp)
		return 0;

	/* Additional RX ring is allocated for PTP HWTS on A1 */
	return (aq_nic->aq_ptp->a1_ptp && ring_type == ATL_RING_RX) ? 2 : 1;
}

u64 *aq_ptp_get_stats(struct aq_nic_s *aq_nic, u64 *data)
{
	struct aq_ptp_s *aq_ptp = aq_nic->aq_ptp;
	unsigned int count = 0U;

	if (!aq_ptp)
		return data;

	count = aq_ring_fill_stats_data(&aq_ptp->ptp_rx, data);
	data += count;
	count = aq_ring_fill_stats_data(&aq_ptp->ptp_tx, data);
	data += count;

	if (aq_ptp->a1_ptp) {
		/* Only Receive ring for HWTS */
		count = aq_ring_fill_stats_data(&aq_ptp->hwts_rx, data);
		data += count;
	}

	return data;
}

EXPORT_SYMBOL_GPL(aq_ptp_configure_ext_gpio);
#endif
