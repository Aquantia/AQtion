/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2018-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

enum aq_state {
	AQDSTATE_REMOVING,
};

struct aq_memreg {
	struct aq_tsn_s *aq_tsn;

	int index;
	void *vaddr; //in-kernel
	dma_addr_t paddr;
	uint32_t size;
	uint32_t real_size;

	/* struct vmarea *mapping; */
	struct list_head list;
	struct kobject kobj;
	struct bin_attribute mmap_attr;
};

struct aq_tsn_bar {
	struct kobject kobj;
	/* struct resource *res; */
	int index;
	phys_addr_t addr;
	phys_addr_t len;
};

struct aq_tsn_s {
	struct aq_nic_s *aq_nic;
	struct mutex memreg_lock;
	long unsigned int state;
	struct kobject *sysfs_bars;
	struct aq_tsn_bar *sysfs_bar[PCI_ROM_RESOURCE]; // 6 BARs excl. ROM

	struct kobject *sysfs_mem;
	struct idr memreg_idr;
	struct list_head mem_regions;
};

extern struct kobj_type memreg_type;

extern int aq_create_attrs(struct aq_tsn_s *dev);
extern void aq_del_attrs(struct aq_tsn_s *dev);
extern int aq_publish_memreg(struct aq_memreg *memreg);
extern void aq_hide_memreg(struct aq_memreg *memreg);
