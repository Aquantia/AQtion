/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_compat.h: Backward compat with previous linux kernel versions */

#ifndef AQ_COMPAT_H
#define AQ_COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

static inline void timer_setup(struct timer_list *timer,
			       void (*callback)(struct timer_list *),
			       unsigned int flags)
{
	setup_timer(timer, (void (*)(unsigned long))callback, (unsigned long)timer);
}

#endif

#ifndef SPEED_5000
#define SPEED_5000 5000
#endif

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU	68
#endif

#ifndef SKB_ALLOC_NAPI
static inline struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int length)
{
	return netdev_alloc_skb_ip_align(napi->dev, length);
}
#endif

#endif /* AQ_COMMON_H */
