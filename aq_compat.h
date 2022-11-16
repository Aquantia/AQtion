/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_compat.h: Backward compat with previous linux kernel versions */

#ifndef AQ_COMPAT_H
#define AQ_COMPAT_H

#include <linux/version.h>
#include <linux/netdevice.h>

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

#ifndef SLE_VERSION
#define SLE_VERSION(a, b, c)	KERNEL_VERSION(a, b, c)
#endif

#ifdef CONFIG_SUSE_KERNEL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 14)
/* SLES15 Beta1 is 4.12.14-2.
 * SLES12 SP4 will also uses 4.12.14-nn.xx.y
 */
#define SLE_VERSION_CODE SLE_VERSION(15, 0, 0)
#else
#error Unsupported SUSE kernel version.
#endif /* LINUX_VERSION_CODE == KERNEL_VERSION(x,y,z) */
#endif /* CONFIG_SUSE_KERNEL */

#ifndef SLE_VERSION_CODE
#define SLE_VERSION_CODE 0
#endif

#ifndef NETIF_F_HW_MACSEC
/* Disable MACSec code, if HW offload is not supported */
#undef CONFIG_MACSEC
#undef CONFIG_MACSEC_MODULE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#if !RHEL_RELEASE_CODE || (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 6))

#ifndef from_timer
#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

static inline void timer_setup(struct timer_list *timer,
			       void (*callback)(struct timer_list *),
			       unsigned int flags)
{
	setup_timer(timer, (void (*)(unsigned long))callback,
		    (unsigned long)timer);
}
#endif

#endif
#endif

#ifndef SPEED_5000
#define SPEED_5000 5000
#endif

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU	68
#endif

#ifndef SKB_ALLOC_NAPI
static inline struct sk_buff *napi_alloc_skb(struct napi_struct *napi,
					     unsigned int length)
{
	return netdev_alloc_skb_ip_align(napi->dev, length);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#if !RHEL_RELEASE_CODE || (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 6))
static inline u64 mul_u32_u32(u32 a, u32 b)
{
	return (u64)a * b;
}
#endif
#endif	/* 4.11.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
/* from commit 1dff8083a024650c75a9c961c38082473ceae8cf */
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#endif	/* 4.7.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)

#if !(RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7, 2)))
/* from commit fe896d1878949ea92ba547587bc3075cc688fb8f */
static inline void page_ref_inc(struct page *page)
{
	atomic_inc(&page->_count);
}

static inline int page_ref_count(struct page *page)
{
	return atomic_read(&page->_count);
}
#endif

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)) && !(RHEL_RELEASE_CODE)
#define napi_complete_done(n, done) napi_complete(n)

#define ETH_RSS_HASH_TOP BIT(0)
#define ETH_RSS_HASH_NO_CHANGE 0
#endif /* 3.19.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)) && !(RHEL_RELEASE_CODE)

/* from commit 286ab723d4b83d37deb4017008ef1444a95cfb0d */
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	memcpy(dst, src, 6);
}
#endif /* 3.14.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) && !(RHEL_RELEASE_CODE)

/* introduced in commit 56193d1bce2b2759cb4bdcc00cd05544894a0c90
 * pull the whole head buffer len for now
 */
#define eth_get_headlen(ndev, __data, __max_len) (__max_len)
#elif RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 2)
#define eth_get_headlen(ndev, data, len) \
	eth_get_headlen(data, len)
#endif /* 3.18.0 */
#endif /* 5.2.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#define IFF_UNICAST_FLT        0
#define dev_alloc_pages(__order) alloc_pages_node(NUMA_NO_NODE, \
						  GFP_ATOMIC |  \
						  __GFP_COMP |  \
						  __GFP_COLD,   \
						  __order)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
/* introduced in commit 71dfda58aaaf4bf6b1bc59f9d8afa635fa1337d4 */
#define dev_alloc_pages(__order) __skb_alloc_pages(GFP_ATOMIC |    \
						   __GFP_COMP,     \
						   NULL, __order)
#endif  /* 3.19.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0) &&\
    RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,3)
#define hlist_add_behind(_a, _b) hlist_add_after(_b, _a)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#if !(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,8) && \
      RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)) && \
    !(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2))
#ifndef timespec64
#define timespec64 timespec
#define timespec64_to_ns timespec_to_ns
#define ns_to_timespec64 ns_to_timespec
#endif
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
#if !RHEL_RELEASE_CODE
#define u64_stats_fetch_begin_irq u64_stats_fetch_begin_bh
#define u64_stats_fetch_retry_irq u64_stats_fetch_retry_bh
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#if !RHEL_RELEASE_CODE
#define u64_stats_init(s)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#define	IPV6_USER_FLOW	0x0e
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)) &&\
    (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2))
#define timecounter_adjtime(tc, delta) do { \
		(tc)->nsec += delta; } while(0)
#define skb_vlan_tag_present(__skb) ((__skb)->vlan_tci & VLAN_TAG_PRESENT)
#define skb_vlan_tag_get(__skb) ((__skb)->vlan_tci & ~VLAN_TAG_PRESENT)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include <linux/iopoll.h>
#else
#define readx_poll_timeout_atomic(op, addr, val, cond, delay_us, timeout_us) \
({ \
	ktime_t timeout = ktime_add_us(ktime_get(), timeout_us); \
	for (;;) { \
		(val) = op(addr); \
		if (cond) \
			break; \
		if (timeout_us && ktime_compare(ktime_get(), timeout) > 0) { \
			(val) = op(addr); \
			break; \
		} \
		if (delay_us) \
			udelay(delay_us);	\
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0)
#ifndef NETIF_F_GSO_UDP_L4
#define NETIF_F_GSO_UDP_L4 0
#endif
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 4)
#define NETIF_F_GSO_PARTIAL 0
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
#if !RHEL_RELEASE_CODE || (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 5))
#ifdef CONFIG_PCI_MSI
#define pci_irq_vector(pdev, nr) \
( \
	(pdev->msix_enabled) ? \
		((struct aq_nic_s *)pci_get_drvdata(pdev))->msix_entry[nr].vector \
		: \
		pdev->irq + nr \
)
#else
#define pci_irq_vector(pdev, nr) \
( \
	pdev->irq \
)
#endif /* CONFIG_PCI_MSI */
#endif /* !RHEL || RHEL < 7.5 */
#endif /* < 4.8.0 */

#if !IS_ENABLED(CONFIG_CRC_ITU_T)
u16 crc_itu_t(u16 crc, const u8 *buffer, size_t len);
#endif

#ifndef IS_REACHABLE
#define IS_REACHABLE defined
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#if !RHEL_RELEASE_CODE || (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 2))
/* Explicitly disable PTP module on kernels 3.16 and 3.10 */
#undef CONFIG_PTP_1588_CLOCK
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 1)
#define dev_open(dev, extack) dev_open(dev)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0) || \
	RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 3) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 6)
#define TC_SETUP_QDISC_MQPRIO TC_SETUP_MQPRIO
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#if !RHEL_RELEASE_CODE || (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 3))
#define NETIF_F_HW_TC 0
#endif
#endif

#ifndef BIT_ULL
#define BIT_ULL(nr)		(1ULL << (nr))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) && \
	RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(8, 6)
#define platform_get_ethdev_address(dev, netdev) (-1)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 6)
static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	memcpy(dev->dev_addr, addr, ETH_ALEN);
}
#endif

#endif /* AQ_COMPAT_H */
