// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2014-2019 aQuantia Corporation
 * Copyright (C) 2019-2020 Marvell International Ltd.
 */

/* File aq_hw_utils.c: Definitions of helper functions used across
 * hardware layer.
 */

#include "aq_hw_utils.h"
#include "aq_hw.h"
#include "aq_nic.h"

void aq_hw_write_reg_bit(struct aq_hw_s *aq_hw, u32 addr, u32 msk,
			 u32 shift, u32 val)
{
	if (msk ^ ~0) {
		u32 reg_old, reg_new;

		reg_old = aq_hw_read_reg(aq_hw, addr);
		reg_new = (reg_old & (~msk)) | (val << shift);

		if (reg_old != reg_new)
			aq_hw_write_reg(aq_hw, addr, reg_new);
	} else {
		aq_hw_write_reg(aq_hw, addr, val);
	}
}

u32 aq_hw_read_reg_bit(struct aq_hw_s *aq_hw, u32 addr, u32 msk, u32 shift)
{
	return ((aq_hw_read_reg(aq_hw, addr) & msk) >> shift);
}

u32 aq_hw_read_reg(struct aq_hw_s *hw, u32 reg)
{
	u32 value = readl(hw->mmio + reg);

	if (value == U32_MAX &&
	    readl(hw->mmio + hw->aq_nic_cfg->aq_hw_caps->hw_alive_check_addr) == U32_MAX)
		aq_utils_obj_set(&hw->flags, AQ_HW_FLAG_ERR_UNPLUG);
#ifdef DEBUG_DUMPREGS
	printk("aq rr 0x%04x: 0x%x\n", reg, value);
#endif
	return value;
}

void aq_hw_write_reg(struct aq_hw_s *hw, u32 reg, u32 value)
{
#ifdef DEBUG_DUMPREGS
	printk("aq wr 0x%04x: 0x%x\n", reg, value);
#endif
	writel(value, hw->mmio + reg);
}

/* Most of 64-bit registers are in LSW, MSW form.
   Counters are normally implemented by HW as latched pairs:
   reading LSW first locks MSW, to overcome LSW overflow
 */
u64 aq_hw_read_reg64(struct aq_hw_s *hw, u32 reg)
{
	u64 value = U64_MAX;
#ifdef CONFIG_X86_64
	if (hw->aq_nic_cfg->aq_hw_caps->op64bit)
		value = readq(hw->mmio + reg);
	else
#endif
	{
		value = aq_hw_read_reg(hw, reg);
		value |= (u64)aq_hw_read_reg(hw, reg + 4) << 32;
	}

	if (value == U64_MAX &&
	    readl(hw->mmio + hw->aq_nic_cfg->aq_hw_caps->hw_alive_check_addr) == U32_MAX)
		aq_utils_obj_set(&hw->flags, AQ_HW_FLAG_ERR_UNPLUG);

	return value;
}

void aq_hw_write_reg64(struct aq_hw_s *hw, u32 reg, u64 value)
{
#ifdef CONFIG_X86_64
	if (hw->aq_nic_cfg->aq_hw_caps->op64bit)
		writeq(value, hw->mmio + reg);
	else
#endif
	{
		writel(lower_32_bits(value), hw->mmio + reg);
		writel(upper_32_bits(value), hw->mmio + reg + sizeof(u32));
	}
}

int aq_hw_err_from_flags(struct aq_hw_s *hw)
{
	int err = 0;

	if (aq_utils_obj_test(&hw->flags, AQ_HW_FLAG_ERR_UNPLUG)) {
		err = -ENXIO;
		goto err_exit;
	}
	if (aq_utils_obj_test(&hw->flags, AQ_HW_FLAG_ERR_HW)) {
		err = -EIO;
		goto err_exit;
	}

err_exit:
	return err;
}

int aq_hw_num_tcs(struct aq_hw_s *hw)
{
	switch (hw->aq_nic_cfg->tc_mode) {
	case AQ_TC_MODE_8TCS:
		return 8;
	case AQ_TC_MODE_4TCS:
		return 4;
	default:
		break;
	}

	return 1;
}

int aq_hw_q_per_tc(struct aq_hw_s *hw)
{
	switch (hw->aq_nic_cfg->tc_mode) {
	case AQ_TC_MODE_8TCS:
		return 4;
	case AQ_TC_MODE_4TCS:
		return 8;
	default:
		return 4;
	}
}
