// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 */

#include "aq_hw.h"
#include "aq_nic.h"

int aq_pci_func_alloc_irq(struct aq_nic_s *self, unsigned int i,
			  char *name, irq_handler_t irq_handler,
			  void *irq_arg, cpumask_t *affinity_mask)
{
	return 0;
}

void aq_pci_func_free_irqs(struct aq_nic_s *self)
{
}

unsigned int aq_pci_func_get_irq_type(struct aq_nic_s *self)
{
	return AQ_HW_IRQ_LEGACY;
}

int aq_pci_func_register_driver(void)
{
	return 0;
}

void aq_pci_func_unregister_driver(void)
{
}
