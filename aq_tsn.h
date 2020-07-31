/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/*
 * File aq_tsn.c: Declaration of TSN functions.
 */

#ifndef aq_tsn_h
#define aq_tsn_h

#define SIOCINITTSN		(SIOCDEVPRIVATE)		/* Initialise TSN support */
#define SIOCRELEASETSN	(SIOCDEVPRIVATE+1)		/* Release TSN support */
#define SIOCLINKCMD		(SIOCDEVPRIVATE+2)		/* Get link status */
#define SIOCALLOCDMABUF	(SIOCDEVPRIVATE+3)		/* Allocate buffer mapped for DMA */
#define SIOCFREEDMABUF	(SIOCDEVPRIVATE+4)		/* Free buffer mapped for DMA */

struct aq_alloc_mem {
	uint32_t size;
    uint32_t index;
	uint64_t paddr;
	void *vaddr; //in-kernel
	void *aq_memreg;
};

#define ATL_LINK_DOWN 0
#define ATL_LINK_100M 1
#define ATL_LINK_1G   2
#define ATL_LINK_2_5G 3
#define ATL_LINK_5G   4
#define ATL_LINK_10G  5

struct atl_link_cmd {
	uint32_t speed; /* 0 - Link down, 1 - 100M, 2 - 1G, 3 - 2.5G, 4 - 5G, 5 - 10G */
};

#ifdef __KERNEL__
int aq_tsn_init(struct aq_nic_s *aq_nic, struct ifreq *ifr);
int aq_tsn_release(struct aq_nic_s *aq_nic, struct ifreq *ifr);

int aq_tsn_alloc_dma_buf(struct aq_nic_s *aq_nic, struct ifreq *ifr);
int aq_tsn_free_dma_buf(struct aq_nic_s *aq_nic, struct ifreq *ifr);

int aq_tsn_get_link(struct aq_nic_s *aq_nic, struct ifreq *ifr);
#endif /*__KERNEL__*/
#endif /* aq_tsn_h */
