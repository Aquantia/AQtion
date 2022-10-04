// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_pci_func.c: Definition of PCI functions. */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/pm_runtime.h>
#include <linux/dma-mapping.h>

#include "aq_main.h"
#include "aq_nic.h"
#include "aq_vec.h"
#include "aq_hw.h"
#include "aq_pci_func.h"
#include "hw_atl/hw_atl_a0.h"
#include "hw_atl/hw_atl_b0.h"
#include "hw_atl2/hw_atl2.h"
#include "aq_filters.h"
#include "aq_drvinfo.h"
#include "aq_macsec.h"

static unsigned int aq_sleep_delay = 10000;
module_param_named(sleep_delay, aq_sleep_delay, uint, 0644);

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

	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC113), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC113DEV), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC113C), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC113CA), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC115C), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC116C), },

	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC113CS), },
	{ PCI_VDEVICE(AQUANTIA, AQ_DEVICE_ID_AQC114CS), },

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

	{ AQ_DEVICE_ID_AQC100,	AQ_HWREV_ANY,	&hw_atl_ops_b1, &hw_atl_b0_caps_aqc100, },
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

	{ AQ_DEVICE_ID_AQC113DEV,	AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc113, },
	{ AQ_DEVICE_ID_AQC113,		AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc113, },
	{ AQ_DEVICE_ID_AQC113C,		AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc113, },
	{ AQ_DEVICE_ID_AQC113CA,	AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc113, },
	{ AQ_DEVICE_ID_AQC115C,		AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc115c, },
	{ AQ_DEVICE_ID_AQC116C,		AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc116c, },

	{ AQ_DEVICE_ID_AQC113CS,	AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc113, },
	{ AQ_DEVICE_ID_AQC114CS,	AQ_HWREV_ANY,	&hw_atl2_ops, &hw_atl2_caps_aqc113, },
};

MODULE_DEVICE_TABLE(pci, aq_pci_tbl);

static int aq_pci_probe_get_hw_by_id(struct pci_dev *pdev,
				     const struct aq_hw_ops **ops,
				     const struct aq_hw_caps_s **caps)
{
	int i;

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
	int err;

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (!err)
		err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (!err)
			err = dma_set_coherent_mask(&pdev->dev,
						    DMA_BIT_MASK(32));
	}
	if (err != 0) {
		err = -ENOSR;
		goto err_exit;
	}

	err = pci_request_regions(pdev, AQ_CFG_DRV_NAME "_mmio");
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
	int err;

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

	return err;
}

void aq_pci_func_free_irqs(struct aq_nic_s *self)
{
	struct pci_dev *pdev = self->pdev;
	unsigned int i;
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

		if (pdev->msix_enabled)
			irq_set_affinity_hint(pci_irq_vector(pdev, i), NULL);
		free_irq(pci_irq_vector(pdev, i), irq_data);

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
	static unsigned int nic_count;
	struct net_device *ndev;
	resource_size_t mmio_pa;
	struct aq_nic_s *self;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	unsigned int i;
#endif
	u32 numvecs;
	u32 bar;
	int err;

	pm_runtime_set_active(&pdev->dev);
	pm_runtime_forbid(&pdev->dev);

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
	if (self->aq_hw->aq_nic_cfg->aq_hw_caps->priv_data_len) {
		int len = self->aq_hw->aq_nic_cfg->aq_hw_caps->priv_data_len;

		self->aq_hw->priv = kzalloc(len, GFP_KERNEL);
		if (!self->aq_hw->priv) {
			err = -ENOMEM;
			goto err_free_aq_hw;
		}
	}

	for (bar = 0; bar < 4; ++bar) {
		if (IORESOURCE_MEM & pci_resource_flags(pdev, bar)) {
			resource_size_t reg_sz;

			mmio_pa = pci_resource_start(pdev, bar);
			if (mmio_pa == 0U) {
				err = -EIO;
				goto err_free_aq_hw_priv;
			}

			reg_sz = pci_resource_len(pdev, bar);
			if ((reg_sz <= 24 /*ATL_REGS_SIZE*/)) {
				err = -EIO;
				goto err_free_aq_hw_priv;
			}

			self->aq_hw->mmio = ioremap(mmio_pa, reg_sz);
			if (!self->aq_hw->mmio) {
				err = -EIO;
				goto err_free_aq_hw_priv;
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
		goto err_free_aq_hw_priv;
	}

	if (self->aq_hw_ops->hw_get_version)
		netdev_info(ndev, "Hardware revision 0x%x\n",
			    self->aq_hw_ops->hw_get_version(self->aq_hw));

	numvecs = min((u8)AQ_CFG_VECS_DEF,
		      aq_nic_get_cfg(self)->aq_hw_caps->msix_irqs);
	numvecs = min(numvecs, num_online_cpus());
	/* Request IRQ lines for PTP and GPIO */
	numvecs += AQ_HW_PTP_IRQS;

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

	aq_nic_parse_parameters(self, nic_count);

	err = aq_nic_ndev_register(self);
	if (err < 0)
		goto err_register;

	aq_drvinfo_init(ndev);

	if (self->aq_hw->aq_fw_ops->get_link_capabilities &&
	    (self->aq_hw->aq_fw_ops->get_link_capabilities(self->aq_hw) &
	     BIT(CAPS_LO_WAKE_ON_LINK_FORCED)))
		pm_runtime_put_noidle(&pdev->dev);

	nic_count++;

	aq_dash_nl_init();
	return 0;

err_register:
	aq_nic_free_vectors(self);
	aq_pci_free_irq_vectors(self);
	if (aq_nic_get_cfg(self)->fw_image)
		release_firmware(aq_nic_get_cfg(self)->fw_image);
err_hwinit:
	iounmap(self->aq_hw->mmio);
err_free_aq_hw_priv:
	kfree(self->aq_hw->priv);
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

	aq_dash_nl_exit();

	if (self->aq_hw->aq_fw_ops->get_link_capabilities &&
	    (self->aq_hw->aq_fw_ops->get_link_capabilities(self->aq_hw) &
	    BIT(CAPS_LO_WAKE_ON_LINK_FORCED)))
		pm_runtime_get_noresume(&pdev->dev);

	if (self->ndev) {
		aq_clear_rxnfc_all_rules(self);
		if (self->ndev->reg_state == NETREG_REGISTERED)
			unregister_netdev(self->ndev);

#if IS_ENABLED(CONFIG_MACSEC)
		aq_macsec_free(self);
#endif
		aq_nic_free_vectors(self);
		aq_pci_free_irq_vectors(self);
		if (aq_nic_get_cfg(self)->fw_image)
			release_firmware(aq_nic_get_cfg(self)->fw_image);
		iounmap(self->aq_hw->mmio);
		kfree(self->aq_hw->priv);
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

static int aq_suspend_common(struct device *dev, u32 wol)
{
	struct aq_nic_s *nic = pci_get_drvdata(to_pci_dev(dev));
	bool rtnlocked;

	rtnlocked = rtnl_trylock();

	nic->power_state = AQ_HW_POWER_STATE_D3;
	netif_tx_stop_all_queues(nic->ndev);

	if (netif_running(nic->ndev)) {
		aq_nic_stop(nic);
		aq_nic_deinit(nic, !wol);
	}

	/* Set WOL config for Suspend/Shutdown */
	if (wol)
		aq_nic_set_power(nic, wol);

	if (rtnlocked)
		rtnl_unlock();

	return 0;
}

static int atl_resume_common(struct device *dev, bool deep)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct aq_nic_s *nic;
	bool rtnlocked;
	int ret = 0;

	nic = pci_get_drvdata(pdev);

	rtnlocked = rtnl_trylock();
	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);

	/* Reinitialize Nic/Vecs objects. Also reset HOST_MODE for HW */
	aq_nic_deinit(nic, true);

	if (aq_utils_obj_test(&nic->aq_hw->flags, AQ_HW_FLAG_STARTED)) {
		ret = aq_nic_init(nic);
		if (ret)
			goto err_exit;

		ret = aq_nic_start(nic);
		if (ret)
			goto err_exit;
	}

	netif_tx_start_all_queues(nic->ndev);

err_exit:
	if (ret < 0)
		aq_nic_deinit(nic, true);

	if (rtnlocked)
		rtnl_unlock();

	return ret;
}

static int aq_pm_freeze(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct aq_nic_s *nic;

	nic = pci_get_drvdata(pdev);

	netif_device_detach(nic->ndev);

	return aq_suspend_common(dev, 0);
}

static int aq_pm_suspend_poweroff(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct aq_nic_s *nic;

	nic = pci_get_drvdata(pdev);

	netif_device_detach(nic->ndev);

	return aq_suspend_common(dev, nic->aq_hw->aq_nic_cfg->wol);
}

static int aq_pm_thaw(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct aq_nic_s *nic;

	nic = pci_get_drvdata(pdev);

	netif_device_attach(nic->ndev);

	return atl_resume_common(dev, false);
}

static int aq_pm_resume_restore(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct aq_nic_s *nic;

	nic = pci_get_drvdata(pdev);

	netif_device_attach(nic->ndev);

	return atl_resume_common(dev, true);
}

static int aq_pm_runtime_resume(struct device *dev)
{
	return atl_resume_common(dev, true);
}

static int aq_pm_runtime_suspend(struct device *dev)
{
	return aq_suspend_common(dev, AQ_FW_WAKE_ON_LINK_RTPM);
}

static int aq_pm_runtime_idle(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct aq_nic_s *self;

	self = pci_get_drvdata(pdev);

	if (!netif_carrier_ok(self->ndev))
		pm_schedule_suspend(&self->pdev->dev, aq_sleep_delay);

	return -EBUSY;
}
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0))
static void aq_reset_prepare(struct pci_dev *pdev)
{
	struct aq_nic_s *nic = pci_get_drvdata(pdev);

	pm_runtime_get_sync(&nic->pdev->dev);
	rtnl_lock();

	if (netif_running(nic->ndev)) {
		if (aq_nic_stop(nic))
			goto unlock;
		aq_nic_deinit(nic, false);
	}

unlock:
	rtnl_unlock();
	pm_runtime_put_sync(&nic->pdev->dev);
}

static void aq_reset_done(struct pci_dev *pdev)
{
	struct aq_nic_s *nic = pci_get_drvdata(pdev);

	if (!nic) {
		dev_err(&pdev->dev, "%s failed, device is unrecoverable\n",
			__func__);
		return;
	}

	pm_runtime_get_sync(&nic->pdev->dev);
	rtnl_lock();

	if (netif_running(nic->ndev)) {
		if (aq_nic_init(nic))
			goto unlock;
		if (aq_nic_start(nic))
			goto unlock;
	}

unlock:
	rtnl_unlock();
	pm_runtime_put_sync(&nic->pdev->dev);
}

static const struct pci_error_handlers aq_err_handlers = {
	.reset_prepare = aq_reset_prepare,
	.reset_done = aq_reset_done,
};

#endif /* > 4.13.0 */

static const struct dev_pm_ops aq_pm_ops = {
	.suspend = aq_pm_suspend_poweroff,
	.poweroff = aq_pm_suspend_poweroff,
	.freeze = aq_pm_freeze,
	.resume = aq_pm_resume_restore,
	.restore = aq_pm_resume_restore,
	.thaw = aq_pm_thaw,
	SET_RUNTIME_PM_OPS(aq_pm_runtime_suspend, aq_pm_runtime_resume,
			   aq_pm_runtime_idle)
};

static struct pci_driver aq_pci_ops = {
	.name = AQ_CFG_DRV_NAME,
	.id_table = aq_pci_tbl,
	.probe = aq_pci_probe,
	.remove = aq_pci_remove,
	.shutdown = aq_pci_shutdown,
#ifdef CONFIG_PM
	.driver.pm = &aq_pm_ops,
#endif
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4, 13, 0))
	.err_handler = &aq_err_handlers,
#endif
};

int aq_pci_func_register_driver(void)
{
	return pci_register_driver(&aq_pci_ops);
}

void aq_pci_func_unregister_driver(void)
{
	pci_unregister_driver(&aq_pci_ops);
}

MODULE_FIRMWARE(AQ_FW_AQC100X);
MODULE_FIRMWARE(AQ_FW_AQC10XX);
MODULE_FIRMWARE(AQ_FW_AQC11XX);
