// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2018-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */
#include "aq_nic.h"
#include "aq_sysfs.h"

#define to_bar(obj) container_of((obj), struct aq_tsn_bar, kobj)
struct bar_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct aq_tsn_bar *, char *);
	ssize_t (*store)(struct aq_tsn_bar *, char*, size_t);
};

#define aqdev_bar_attr(_field, _fmt)					\
	static ssize_t							\
	bar_##_field##_show(struct aq_tsn_bar *bar, char *buf)		\
	{								\
		return sprintf(buf, _fmt, bar->_field);			\
	}								\
	static struct bar_sysfs_entry bar_##_field##_attr =		\
		__ATTR(_field, S_IRUGO, bar_##_field##_show, NULL);

#pragma GCC diagnostic ignored "-Wformat"
aqdev_bar_attr(addr, "0x%lx\n");
aqdev_bar_attr(len, "0x%lx\n");
aqdev_bar_attr(index, "%d\n");
#pragma GCC diagnostic warning "-Wformat"

static ssize_t bar_attr_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct aq_tsn_bar *bar = to_bar(kobj);
	struct bar_sysfs_entry *entry =
		container_of(attr, struct bar_sysfs_entry, attr);

	if (!entry->show)
		return -EIO;

	return entry->show(bar, buf);
}

static const struct sysfs_ops bar_ops = {
	.show = bar_attr_show,
};

static void bar_release(struct kobject *kobj)
{
	struct aq_tsn_bar *bar = to_bar(kobj);
	kfree(bar);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
static struct attribute *bar_attrs[] = {
	&bar_addr_attr.attr,
	&bar_len_attr.attr,
	&bar_index_attr.attr,
	NULL,
};
#else

#define BAR_ATTRIBUTE_GROUPS(_name)  \
struct attribute *bar##_name##_attr = &bar_##_name##_attr.attr; \
static const struct attribute_group bar_##_name##_group = { \
	.attrs = &bar##_name##_attr, \
};

BAR_ATTRIBUTE_GROUPS(addr);
BAR_ATTRIBUTE_GROUPS(len);
BAR_ATTRIBUTE_GROUPS(index);

const struct attribute_group *bar_attrs_grp[] = {
	&bar_addr_group,
	&bar_len_group,
	&bar_index_group,
	NULL,
};
#endif

static struct kobj_type bar_type = {
	.sysfs_ops = &bar_ops,
	.release = bar_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	.default_attrs = bar_attrs,
#else
	.default_groups = bar_attrs_grp,
#endif
};

static void aq_release_bars(struct aq_tsn_s *self)
{
	int i;

	for (i = 0; i < PCI_ROM_RESOURCE; i++) {
		struct aq_tsn_bar *bar = self->sysfs_bar[i];
		if (!bar)
			continue;
		kobject_del(&bar->kobj);
		kobject_put(&bar->kobj);
	}

	kobject_del(self->sysfs_bars);
	kobject_put(self->sysfs_bars);
}

static int aq_create_bars(struct aq_tsn_s *self)
{
	int ret;
	int mask = pci_select_bars(self->aq_nic->pdev, IORESOURCE_MEM | IORESOURCE_IO);
	int i;
	struct aq_tsn_bar *bar;

	ret = -EINVAL;
	self->sysfs_bars = kobject_create_and_add("bars", &aq_nic_get_dev(self->aq_nic)->kobj);
	if (!self->sysfs_bars)
		goto err;

	for (i = 0; mask && i < PCI_ROM_RESOURCE; mask >>= 1, i++){
		const char *pref = pci_resource_flags(self->aq_nic->pdev, i) & IORESOURCE_MEM ? "mem" : "io";

		if (!(mask & 1))
			continue;

		ret = -ENOMEM;
		bar = kzalloc(sizeof(*bar), GFP_KERNEL);
		if (!bar)
			goto err;
		kobject_init(&bar->kobj, &bar_type);
		bar->index = i;
		bar->addr = pci_resource_start(self->aq_nic->pdev, i);
		bar->len = pci_resource_len(self->aq_nic->pdev, i);
		self->sysfs_bar[i] = bar;
		ret = kobject_add(&bar->kobj, self->sysfs_bars, "%sbar%d", pref, i);
		if (ret)
			goto err;
	}

	return 0;

err:
	aq_release_bars(self);
	return ret;
}

int aq_create_attrs(struct aq_tsn_s *self)
{
	int ret = -EINVAL;

	self->sysfs_mem = kobject_create_and_add("mem", &aq_nic_get_dev(self->aq_nic)->kobj);
	if (!self->sysfs_mem)
		goto err_mem;

	ret = aq_create_bars(self);
	if (ret)
		goto err_bar;

	return 0;

err_bar:
	kobject_del(self->sysfs_mem);
	kobject_put(self->sysfs_mem);
err_mem:
	dev_err(aq_nic_get_dev(self->aq_nic), "Couldn't create sysfs files: %d\n", ret);
	return ret;
}

void aq_del_attrs(struct aq_tsn_s *self)
{
	aq_release_bars(self);
	kobject_del(self->sysfs_mem);
	kobject_put(self->sysfs_mem);
}

#define to_memreg(obj) container_of(obj, struct aq_memreg, kobj)
struct memreg_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct aq_memreg *, char *);
	ssize_t (*store)(struct aq_memreg *, char*, size_t);
};

#define aqdev_memreg_attr(_field, _fmt)					\
	static ssize_t							\
	memreg_##_field##_show(struct aq_memreg *memreg, char *buf)	\
	{								\
		return sprintf(buf, _fmt, memreg->_field);		\
	}								\
	static struct memreg_sysfs_entry memreg_##_field##_attr =	\
		__ATTR(_field, S_IRUGO, memreg_##_field##_show, NULL);

#pragma GCC diagnostic ignored "-Wformat"
aqdev_memreg_attr(vaddr, "0x%lx\n");
aqdev_memreg_attr(paddr, "0x%lx\n");
aqdev_memreg_attr(size, "0x%x\n");
aqdev_memreg_attr(real_size, "0x%x\n");
aqdev_memreg_attr(index, "%d\n");
#pragma GCC diagnostic warning "-Wformat"

static ssize_t memreg_attr_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct aq_memreg *memreg = to_memreg(kobj);
	struct memreg_sysfs_entry *entry =
		container_of(attr, struct memreg_sysfs_entry, attr);

	if (!entry->show)
		return -EIO;

	return entry->show(memreg, buf);
}

static const struct sysfs_ops memreg_ops = {
	.show = memreg_attr_show,
};

static void memreg_release(struct kobject *kobj)
{
	struct aq_memreg *memreg = to_memreg(kobj);
	kfree(memreg);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
static struct attribute *memreg_attrs[] = {
	&memreg_vaddr_attr.attr,
	&memreg_paddr_attr.attr,
	&memreg_size_attr.attr,
	&memreg_real_size_attr.attr,
	&memreg_index_attr.attr,
	NULL,
};
#else

#define MEMREG_ATTRIBUTE_GROUPS(_name)  \
struct attribute *memreg##_name##_attr = &memreg_##_name##_attr.attr; \
static const struct attribute_group memreg_##_name##_group = { \
	.attrs = &memreg##_name##_attr,  \
};

MEMREG_ATTRIBUTE_GROUPS(vaddr);
MEMREG_ATTRIBUTE_GROUPS(paddr);
MEMREG_ATTRIBUTE_GROUPS(size);
MEMREG_ATTRIBUTE_GROUPS(real_size);
MEMREG_ATTRIBUTE_GROUPS(index);

static const struct attribute_group *memreg_attrs_grp[] = {
	&memreg_vaddr_group,
	&memreg_paddr_group,
	&memreg_size_group,
	&memreg_real_size_group,
	&memreg_index_group,
	NULL,
};
#endif

struct kobj_type memreg_type = {
	.sysfs_ops = &memreg_ops,
	.release = memreg_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	.default_attrs = memreg_attrs,
#else
	.default_groups = memreg_attrs_grp,
#endif
};

static int memreg_mmap(struct file *file, struct kobject *kobj, struct bin_attribute *attr,
		       struct vm_area_struct *vma)
{
	struct aq_memreg *memreg = attr->private;
	unsigned long requested = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	unsigned long pages = (unsigned long)memreg->real_size >> PAGE_SHIFT;

	if (vma->vm_pgoff + requested > pages)
		return -EINVAL;
	
#if defined(__arm__) || defined(__aarch64__)
	// had issues with writes to descriptors/packets not being seen by HW for arm systems. this function seemed to fix this
#ifdef pgprot_dmacoherent
	vma->vm_page_pgprot = prot_dmacoherent(vma->vm_page_prot);
#else //!defined(pgprot_dmacoherent)
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	//vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
#endif //defined(pgprot_dmacoherent)
#endif

	if (remap_pfn_range(vma, vma->vm_start, memreg->paddr >> PAGE_SHIFT,
			    vma->vm_end - vma->vm_start, vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}

int aq_publish_memreg(struct aq_memreg *memreg)
{
	int ret;
	struct bin_attribute *mmap_attr = &memreg->mmap_attr;

	ret = kobject_add(&memreg->kobj, memreg->aq_tsn->sysfs_mem,
			  "%d", memreg->index);
	if (ret)
		goto err_add;

	mmap_attr->mmap = memreg_mmap;
	mmap_attr->attr.name = "mmap";
	mmap_attr->attr.mode = S_IRUSR | S_IWUSR;
	mmap_attr->size = memreg->real_size;
	mmap_attr->private = memreg;
	ret = sysfs_create_bin_file(&memreg->kobj, mmap_attr);
	if (ret)
		goto err_map_add;

	return 0;

err_map_add:
	kobject_del(&memreg->kobj);
err_add:
	kobject_put(&memreg->kobj);
	return ret;
}

void aq_hide_memreg(struct aq_memreg *memreg)
{
	sysfs_remove_bin_file(&memreg->kobj, &memreg->mmap_attr);
	kobject_del(&memreg->kobj);
	kobject_put(&memreg->kobj);
}

