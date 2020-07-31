// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/*
 * File aq_tsn.c:
 * Definition of functions for TSN network support.
 */

#include "aq_nic.h"
#include "aq_hw.h"
#include "aq_ptp.h"
#include "aq_tsn.h"
#include "aq_ring.h"
#include "aq_nic.h"
#include "aq_hw_utils.h"
#include "aq_main.h"

#include "aq_sysfs.h"

#include <linux/moduleparam.h>

#ifdef TSN_SUPPORT

static int aq_get_link_status(struct aq_tsn_s *self, struct atl_link_cmd __user *ureq)
{
	struct atl_link_cmd link = {ATL_LINK_DOWN};

	switch(self->aq_nic->link_status.mbps)
	{
		case 100U:
			link.speed = ATL_LINK_100M;
			break;
		case 1000U:
			link.speed = ATL_LINK_1G;
			break;
		case 2500U:
			link.speed = ATL_LINK_2_5G;
			break;
		case 5000U:
			link.speed = ATL_LINK_5G;
			break;
		case 10000U:
			link.speed = ATL_LINK_10G;
			break;
	}
	return copy_to_user(ureq, &link, sizeof(link));
}
// aq_tsn->memreg_lock must be held
static void __aq_unlink_mem(struct aq_memreg *memreg)
{
	idr_remove(&memreg->aq_tsn->memreg_idr, memreg->index);
	list_del(&memreg->list);
}

static void aq_free_mem(struct aq_memreg *memreg)
{
	aq_hide_memreg(memreg);

	dma_free_coherent(aq_nic_get_dev(memreg->aq_tsn->aq_nic), memreg->real_size,
			  memreg->vaddr, memreg->paddr);
	kobject_put(&memreg->kobj);
}

static int aq_allocate_buffer(struct aq_tsn_s *self, struct aq_alloc_mem __user *ureq)
{
	int idx;
	int ret = -ENOMEM;
	struct aq_memreg *memreg;
	struct aq_alloc_mem req;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	memreg = kzalloc(sizeof(*memreg), GFP_KERNEL);
	if (!memreg) {
		pr_err("AQ_TSN : Can't alloc memreg\n");
		goto out;
	}
	INIT_LIST_HEAD(&memreg->list);
	memreg->aq_tsn = self;
	kobject_init(&memreg->kobj, &memreg_type);

	memreg->size = req.size;
	req.size = ALIGN(req.size, PAGE_SIZE);
	memreg->vaddr = dma_alloc_coherent(aq_nic_get_dev(self->aq_nic), req.size, &memreg->paddr, GFP_KERNEL);
	if (!memreg->vaddr) {
		pr_err("AQ_TSN : Can't alloc DMA memory (size %u)", req.size);
		goto err_dma_alloc;
	}
	memreg->real_size = req.size;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,15,0)
	do {
		ret = -ENOMEM;
		if (!idr_pre_get(&self->memreg_idr, GFP_KERNEL))
			goto err_idr;

		mutex_lock(&self->memreg_lock);
		if (test_bit(AQDSTATE_REMOVING, &self->state))
			ret = -ENODEV;
		else
			ret = idr_get_new(&self->memreg_idr, memreg, &idx);
		mutex_unlock(&self->memreg_lock);
	} while (ret == -EAGAIN);
	if (ret)
		goto err_idr;
	memreg->index = req.index = idx;
#else
	idr_preload(GFP_KERNEL);
	mutex_lock(&self->memreg_lock);
	ret = idr_alloc(&self->memreg_idr, memreg,
		0, 0, GFP_KERNEL);
	mutex_unlock(&self->memreg_lock);
	idr_preload_end();
	if (ret < 0)
		goto err_idr;
	memreg->index = req.index = idx = ret;
#endif

	ret = aq_publish_memreg(memreg);
	if (ret) {
		dev_err(aq_nic_get_dev(self->aq_nic), "Can't publish memreg to sysfs: %d", ret);
		goto err_publish;
	}

	if(copy_to_user(ureq, &req, sizeof(req))) {
		ret = -EFAULT;
		goto err_copy_to_user;
	}

	mutex_lock(&self->memreg_lock);
	list_add(&memreg->list, &self->mem_regions);
	mutex_unlock(&self->memreg_lock);

	return 0;

err_copy_to_user:
	aq_hide_memreg(memreg);
err_publish:
	mutex_lock(&self->memreg_lock);
	idr_remove(&self->memreg_idr, idx);
	mutex_unlock(&self->memreg_lock);
err_idr:
	dma_free_coherent(aq_nic_get_dev(self->aq_nic), memreg->real_size,
			  memreg->vaddr, memreg->paddr);
err_dma_alloc:
	kobject_put(&memreg->kobj);
out:
	return ret;
}

int aq_tsn_init(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	int err = -ENOMEM;
	struct aq_tsn_s *self = aq_nic->aq_tsn;

	if (self) // TSN is already initialised
		return 0;
	self = kzalloc(sizeof(*self), GFP_KERNEL);
	if (!self) {
		pr_err("AQ_TSN : Can't alloc aq_tsn\n");
		goto out;
	}

	idr_init(&self->memreg_idr);
	mutex_init(&self->memreg_lock);
	INIT_LIST_HEAD(&self->mem_regions);

	self->aq_nic = aq_nic;
	err = aq_create_attrs(self);
	if (err) {
		kfree(self);
		goto out;
	}
	aq_nic->aq_tsn = self;
out:
	return err;
}

int aq_tsn_release(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	int err = 0;
	struct aq_tsn_s *self = aq_nic->aq_tsn;
	struct aq_memreg *memreg, *tmp;
	struct list_head memregs;

	if (!self)  // TSN is uninitialised
		return 0;

	aq_nic->aq_tsn = NULL; // TODO Issue if there is a thread which sleeps before prev cond and next step

	aq_del_attrs(self);

	mutex_lock(&self->memreg_lock);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,15,0)
	idr_remove_all(&self->memreg_idr);
#endif
	idr_destroy(&self->memreg_idr);
	list_replace_init(&self->mem_regions, &memregs);
	mutex_unlock(&self->memreg_lock);
	list_for_each_entry_safe(memreg, tmp, &memregs, list)
		aq_free_mem(memreg);

	mutex_destroy(&self->memreg_lock);
	kfree(self);

	return err;
}

int aq_tsn_alloc_dma_buf(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	int err = 0;
	struct aq_tsn_s *self = aq_nic->aq_tsn;

	if (!self)  // TSN is uninitialised
		return 0;

	err = aq_allocate_buffer(self, (struct aq_alloc_mem __user *) ifr->ifr_data);
	if (err == -ERESTARTSYS)
		err = -EINTR; // Never restart if interrupted by a signal

	return err;
}

int aq_tsn_free_dma_buf(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	int err = 0;
	struct aq_tsn_s *self = aq_nic->aq_tsn;
	struct aq_memreg *memreg;

	if (!self)  // TSN is uninitialised
		return 0;

	mutex_lock(&self->memreg_lock);
	memreg = idr_find(&self->memreg_idr, ifr->ifr_metric);
	if (memreg)
		__aq_unlink_mem(memreg);
	mutex_unlock(&self->memreg_lock);

	if (!memreg)
		return -ENOENT;
	aq_free_mem(memreg);

	return err;
}

int aq_tsn_get_link(struct aq_nic_s *aq_nic, struct ifreq *ifr)
{
	struct aq_tsn_s *self = aq_nic->aq_tsn;

	if (!self)  // TSN is uninitialised
		return 0;

	return aq_get_link_status(self, (struct atl_link_cmd __user *) ifr->ifr_data);
}

#endif


//EOF
