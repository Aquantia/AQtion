/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_pci_func.c: Definition of PCI functions. */

#include <linux/module.h>

#include "aq_main.h"
#include "aq_nic.h"
#include "aq_vec.h"
#include "aq_hw.h"
#include "aq_ptp.h"
#include "aq_pci_func.h"
#include "hw_atl/hw_atl_a0.h"
#include "hw_atl/hw_atl_b0.h"
#include "aq_filters.h"

static const struct pci_device_id aq_pci_tbl[] = {
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_0001), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_D100), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_D107), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_D108), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_D109), },

	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC100), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC107), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC108), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC109), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC111), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC112), },

	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC100S), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC107S), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC108S), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC109S), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC111S), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC112S), },

	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC111E), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC112E), },

	{}
};

static const struct aq_board_revision_s hw_atl_boards[] = {
	{ AQ_DEVICE_ID_0001,	AQ_HWREV_1,	&hw_atl_ops_a0, &hw_atl_a0_caps_aqc107, },
	{ AQ_DEVICE_ID_D100,	AQ_HWREV_1,	&hw_atl_ops_a0, &hw_atl_a0_caps_aqc100, },
	{ AQ_DEVICE_ID_D107,	AQ_HWREV_1,	&hw_atl_ops_a0, &hw_atl_a0_caps_aqc107, },
	{ AQ_DEVICE_ID_D108,	AQ_HWREV_1,	&hw_atl_ops_a0, &hw_atl_a0_caps_aqc108, },
	{ AQ_DEVICE_ID_D109,	AQ_HWREV_1,	&hw_atl_ops_a0, &hw_atl_a0_caps_aqc109, },

	{ AQ_DEVICE_ID_0001,	AQ_HWREV_2,	&hw_atl_ops_b0, &hw_atl_b0_caps_aqc107, },
	{ AQ_DEVICE_ID_D100,	AQ_HWREV_2,	&hw_atl_ops_b0, &hw_atl_b0_caps_aqc100, },
	{ AQ_DEVICE_ID_D107,	AQ_HWREV_2,	&hw_atl_ops_b0, &hw_atl_b0_caps_aqc107, },
	{ AQ_DEVICE_ID_D108,	AQ_HWREV_2,	&hw_atl_ops_b0, &hw_atl_b0_caps_aqc108, },
	{ AQ_DEVICE_ID_D109,	AQ_HWREV_2,	&hw_atl_ops_b0, &hw_atl_b0_caps_aqc109, },

	{ AQ_DEVICE_ID_AQC100,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc107, },
	{ AQ_DEVICE_ID_AQC107,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc107, },
	{ AQ_DEVICE_ID_AQC108,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc108, },
	{ AQ_DEVICE_ID_AQC109,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc109, },
	{ AQ_DEVICE_ID_AQC111,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc111, },
	{ AQ_DEVICE_ID_AQC112,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc112, },

	{ AQ_DEVICE_ID_AQC100S,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc100s, },
	{ AQ_DEVICE_ID_AQC107S,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc107s, },
	{ AQ_DEVICE_ID_AQC108S,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc108s, },
	{ AQ_DEVICE_ID_AQC109S,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc109s, },
	{ AQ_DEVICE_ID_AQC111S,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc111s, },
	{ AQ_DEVICE_ID_AQC112S,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc112s, },

	{ AQ_DEVICE_ID_AQC111E,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc111e, },
	{ AQ_DEVICE_ID_AQC112E,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc112e, },
};

MODULE_DEVICE_TABLE(pci, aq_pci_tbl);

static int aq_pci_probe_get_hw_by_id(struct pci_dev *pdev,
				     const struct aq_hw_ops **ops,
				     const struct aq_hw_caps_s **caps)
{
	int i = 0;

	if (pdev->vendor != PCI_VENDOR_ID_AQUANTIA)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(hw_atl_boards); i++) {
		if (hw_atl_boards[i].devid == pdev->device &&
		    (hw_atl_boards[i].revision == AQ_HWREV_ANY ||
		     hw_atl_boards[i].revision == pdev->revision)) {
			*ops = hw_atl_boards[i].ops;
			*caps = hw_atl_boards[i].caps;
			break;
		}
	}

	if (i == ARRAY_SIZE(hw_atl_boards))
		return -EINVAL;

	return 0;
}

static int aq_pci_func_init(struct pci_dev *pdev)
{
	int err = 0;

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (!err)
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (!err)
			err = pci_set_consistent_dma_mask(pdev,
							  DMA_BIT_MASK(32));
	}
	if (err != 0) {
		err = -ENOSR;
		goto err_exit;
	}

	err = pci_request_regions(pdev, aq_ndev_driver_name);
	if (err < 0)
		goto err_exit;

	pci_set_master(pdev);

	return 0;

err_exit:
	return err;
}

int aq_pci_func_alloc_irq(struct aq_nic_s *self, unsigned int i,
			  char *name, irq_handler_t irq_handler,
			  void *irq_arg, cpumask_t *affinity_mask)
{
	struct pci_dev *pdev = self->pdev;
	int err = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	if (pdev->msix_enabled)
		err = request_irq(self->msix_entry[i].vector, irq_handler, 0,
				  name, irq_arg);
	else if (pdev->msi_enabled)
		err = request_irq(pdev->irq, irq_handler, 0, name, irq_arg);
	else
		err = request_irq(pdev->irq, aq_vec_isr_legacy,
				  IRQF_SHARED, name, irq_arg);

	if (err >= 0) {
		self->msix_entry_mask |= (1 << i);

		if (pdev->msix_enabled && affinity_mask)
			irq_set_affinity_hint(self->msix_entry[i].vector,
					      affinity_mask);
	}
#else
	if (pdev->msix_enabled || pdev->msi_enabled)
		err = request_irq(pci_irq_vector(pdev, i), irq_handler, 0,
				  name, irq_arg);
	else
		err = request_irq(pci_irq_vector(pdev, i), aq_vec_isr_legacy,
				  IRQF_SHARED, name, irq_arg);

	if (err >= 0) {
		self->msix_entry_mask |= (1 << i);

		if (pdev->msix_enabled && affinity_mask)
			irq_set_affinity_hint(pci_irq_vector(pdev, i),
					      affinity_mask);
	}
#endif
	return err;
}

void aq_pci_func_free_irqs(struct aq_nic_s *self)
{
	struct pci_dev *pdev = self->pdev;
	unsigned int i = 0U;
	void *irq_data;

	for (i = 32U; i--;) {

		if (!((1U << i) & self->msix_entry_mask))
			continue;
		if (self->aq_nic_cfg.link_irq_vec &&
		    i == self->aq_nic_cfg.link_irq_vec)
			irq_data = self;
		else if (i < AQ_CFG_VECS_MAX)
			irq_data = self->aq_vec[i];
		else
			continue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		switch (aq_pci_func_get_irq_type(self)) {
		case AQ_HW_IRQ_MSIX:
			irq_set_affinity_hint(self->msix_entry[i].vector, NULL);
			free_irq(self->msix_entry[i].vector, irq_data);
			break;

		case AQ_HW_IRQ_MSI:
			free_irq(pdev->irq, irq_data);
			break;

		case AQ_HW_IRQ_LEGACY:
			free_irq(pdev->irq, irq_data);
			break;

		default:
			break;
		}

#else
		if (pdev->msix_enabled)
			irq_set_affinity_hint(pci_irq_vector(pdev, i), NULL);
		free_irq(pci_irq_vector(pdev, i), irq_data);
#endif
		self->msix_entry_mask &= ~(1U << i);
	}
}

unsigned int aq_pci_func_get_irq_type(struct aq_nic_s *self)
{
	if (self->pdev->msix_enabled)
		return AQ_HW_IRQ_MSIX;
	if (self->pdev->msi_enabled)
		return AQ_HW_IRQ_MSI;
	return AQ_HW_IRQ_LEGACY;
}

static void aq_pci_free_irq_vectors(struct aq_nic_s *self)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)

	switch (aq_pci_func_get_irq_type(self)) {
	case AQ_HW_IRQ_MSI:
		pci_disable_msi(self->pdev);
		break;

	case AQ_HW_IRQ_MSIX:
		pci_disable_msix(self->pdev);
		break;

	case AQ_HW_IRQ_LEGACY:
		break;

	default:
		break;
	}

#else
	pci_free_irq_vectors(self->pdev);

#endif
}

static int aq_pci_probe(struct pci_dev *pdev,
			const struct pci_device_id *pci_id)
{
	struct aq_nic_s *self = NULL;
	int err = 0;
	struct net_device *ndev;
	resource_size_t mmio_pa;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	unsigned int i = 0U;
#endif
	u32 bar;
	u32 numvecs;

	err = pci_enable_device(pdev);
	if (err)
		return err;

	err = aq_pci_func_init(pdev);
	if (err)
		goto err_pci_func;

	ndev = aq_ndev_alloc();
	if (!ndev) {
		err = -ENOMEM;
		goto err_ndev;
	}

	self = netdev_priv(ndev);
	self->pdev = pdev;
	SET_NETDEV_DEV(ndev, &pdev->dev);
	pci_set_drvdata(pdev, self);

	mutex_init(&self->fwreq_mutex);

	err = aq_pci_probe_get_hw_by_id(pdev, &self->aq_hw_ops,
					&aq_nic_get_cfg(self)->aq_hw_caps);
	if (err)
		goto err_ioremap;

	self->aq_hw = kzalloc(sizeof(*self->aq_hw), GFP_KERNEL);
	if (!self->aq_hw) {
		err = -ENOMEM;
		goto err_ioremap;
	}
	self->aq_hw->aq_nic_cfg = aq_nic_get_cfg(self);

	for (bar = 0; bar < 4; ++bar) {
		if (IORESOURCE_MEM & pci_resource_flags(pdev, bar)) {
			resource_size_t reg_sz;

			mmio_pa = pci_resource_start(pdev, bar);
			if (mmio_pa == 0U) {
				err = -EIO;
				goto err_free_aq_hw;
			}

			reg_sz = pci_resource_len(pdev, bar);
			if ((reg_sz <= 24 /*ATL_REGS_SIZE*/)) {
				err = -EIO;
				goto err_free_aq_hw;
			}

			self->aq_hw->mmio = ioremap_nocache(mmio_pa, reg_sz);
			if (!self->aq_hw->mmio) {
				err = -EIO;
				goto err_free_aq_hw;
			}

#ifdef PCI_DEBUG
			if (IORESOURCE_BUSY &
			    pdev->resource[bar].child->flags) {
				struct resource *res;

				res = pdev->resource[bar].child;
				res->flags &= ~IORESOURCE_BUSY;
				aq_utils_obj_set(&self->flags,
						 AQ_NIC_PCI_RESOURCE_BUSY);
				netdev_info(ndev, "Fix resource %d child flag,"
					    " new: %x\n", bar,
					    (uint32_t)res->flags);
			}
#endif
			break;
		}
	}

	if (bar == 4) {
		err = -EIO;
		goto err_free_aq_hw;
	}

	if (self->aq_hw_ops->hw_get_version)
		netdev_info(ndev, "Hardware revision 0x%x\n",
			    self->aq_hw_ops->hw_get_version(self->aq_hw));

	numvecs = min((u8)AQ_CFG_VECS_DEF,
		      aq_nic_get_cfg(self)->aq_hw_caps->msix_irqs);
	numvecs = min(numvecs, num_online_cpus());
	numvecs += 1; // Request IRQ vector for PTP

	numvecs += AQ_HW_SERVICE_IRQS;

	/*enable interrupts */
#if !AQ_CFG_FORCE_LEGACY_INT
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	for (i = 0; i < numvecs; i++)
		self->msix_entry[i].entry = i;

	err = pci_enable_msix(self->pdev, self->msix_entry, numvecs);

	if (err < 0) {
		err = pci_enable_msi(self->pdev);

		if (err < 0)
			goto err_hwinit;
	}
#else
	err = pci_alloc_irq_vectors(self->pdev, 1, numvecs,
				    PCI_IRQ_MSIX | PCI_IRQ_MSI |
				    PCI_IRQ_LEGACY);

	if (err < 0)
		goto err_hwinit;
	numvecs = err;
#endif
#endif
	self->irqvecs = numvecs;

	/* net device init */
	aq_nic_cfg_start(self);

	aq_nic_ndev_init(self);

	err = aq_nic_ndev_register(self);
	if (err < 0)
		goto err_register;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	err = aq_ptp_init(self, numvecs - 1, self->msix_entry[numvecs - 1].vector);
#else
	err = aq_ptp_init(self, numvecs - 1);
#endif
#endif
	if (err < 0)
		goto err_register;

	return 0;

err_register:
	aq_nic_free_vectors(self);
	aq_pci_free_irq_vectors(self);
err_hwinit:
	iounmap(self->aq_hw->mmio);
err_free_aq_hw:
	kfree(self->aq_hw);
err_ioremap:
	free_netdev(ndev);
err_ndev:
	pci_release_regions(pdev);
err_pci_func:
	pci_disable_device(pdev);
	return err;
}

static void aq_pci_remove(struct pci_dev *pdev)
{
	struct aq_nic_s *self = pci_get_drvdata(pdev);

	if (self->ndev) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))
		aq_ptp_unregister(self);
#endif
		aq_clear_rxnfc_all_rules(self);
		if (self->ndev->reg_state == NETREG_REGISTERED)
			unregister_netdev(self->ndev);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) ||\
    (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2))
		aq_ptp_ring_free(self);
		aq_ptp_free(self);
#endif
		
		aq_nic_free_vectors(self);
		aq_pci_free_irq_vectors(self);
		iounmap(self->aq_hw->mmio);
		kfree(self->aq_hw);

#ifdef PCI_DEBUG
		if (aq_utils_obj_test(&self->flags, AQ_NIC_PCI_RESOURCE_BUSY)) {
			u32 bar;

			for (bar = 0; bar < 4; ++bar) {
				if (IORESOURCE_MEM &
				    pci_resource_flags(pdev, bar)) {
					struct resource *res;

					res = pdev->resource[bar].child;
					res->flags |= IORESOURCE_BUSY;
					aq_utils_obj_clear(&self->flags,
							   AQ_NIC_PCI_RESOURCE_BUSY);
					netdev_info(self->ndev,
						    "Restore resource %d "
						    "child flag, new: %x\n",
						    bar, (uint32_t)res->flags);
					break;
				}
			}
		}
#endif

		pci_release_regions(pdev);
		free_netdev(self->ndev);
	}

	pci_disable_device(pdev);
}

static void aq_pci_shutdown(struct pci_dev *pdev)
{
	struct aq_nic_s *self = pci_get_drvdata(pdev);

	aq_nic_shutdown(self);

	pci_disable_device(pdev);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, !!self->aq_nic_cfg.wol);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

static int aq_pci_suspend(struct pci_dev *pdev, pm_message_t pm_msg)
{
	struct aq_nic_s *self = pci_get_drvdata(pdev);

	return aq_nic_change_pm_state(self, &pm_msg);
}

static int aq_pci_resume(struct pci_dev *pdev)
{
	struct aq_nic_s *self = pci_get_drvdata(pdev);
	pm_message_t pm_msg = PMSG_RESTORE;

	return aq_nic_change_pm_state(self, &pm_msg);
}

static struct pci_driver aq_pci_ops = {
	.name = aq_ndev_driver_name,
	.id_table = aq_pci_tbl,
	.probe = aq_pci_probe,
	.remove = aq_pci_remove,
	.suspend = aq_pci_suspend,
	.resume = aq_pci_resume,
	.shutdown = aq_pci_shutdown,
};

int aq_pci_func_register_driver(void)
{
	return pci_register_driver(&aq_pci_ops);
}

void aq_pci_func_unregister_driver(void)
{
	pci_unregister_driver(&aq_pci_ops);
}
