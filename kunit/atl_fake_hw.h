/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 */

#ifndef ATL_FAKE_HW_H
#define ATL_FAKE_HW_H

#include <linux/types.h>

struct aq_hw_s;
struct kunit;

struct atl_hw {
	void (*write_reg_bit)(struct atl_hw *parent, struct aq_hw_s *aq_hw,
			      u32 addr, u32 msk, u32 shift, u32 val);
	u32 (*read_reg_bit)(struct atl_hw *parent, struct aq_hw_s *aq_hw,
			    u32 addr, u32 msk, u32 shift);
	u32 (*read_reg)(struct atl_hw *parent, struct aq_hw_s *hw, u32 reg);
	void (*write_reg)(struct atl_hw *parent, struct aq_hw_s *hw, u32 reg,
			  u32 value);
	u64 (*read_reg64)(struct atl_hw *parent, struct aq_hw_s *hw, u32 reg);
	int (*err_from_flags)(struct atl_hw *parent, struct aq_hw_s *hw);
};

struct fake_hw_priv;

struct fake_hw {
	struct atl_hw parent;
	struct kunit *test;
	struct fake_hw_priv *priv;

	void (*expect_called)(void *func);
	void (*expect_called_n_times)(void *func, const unsigned int n_times);
};

void fake_hw_init(struct fake_hw *this, struct kunit *test);
void fake_hw_cleanup(struct fake_hw *this);

#define FAKE_HW_FUNC_PTR(func_name) (&FAKE_HW_FUNC_NAME(func_name))
#define FAKE_HW_FUNC_NAME(func_name) fake_ ## func_name

#define aq_hw_write_reg_bit FAKE_HW_FUNC_NAME(aq_hw_write_reg_bit)
#define aq_hw_read_reg_bit FAKE_HW_FUNC_NAME(aq_hw_read_reg_bit)
#define aq_hw_read_reg FAKE_HW_FUNC_NAME(aq_hw_read_reg)
#define aq_hw_write_reg FAKE_HW_FUNC_NAME(aq_hw_write_reg)
#define aq_hw_read_reg64 FAKE_HW_FUNC_NAME(aq_hw_read_reg64)
#define aq_hw_err_from_flags FAKE_HW_FUNC_NAME(aq_hw_err_from_flags)

#include "aq_hw_utils.h"

#endif /* ATL_FAKE_HW_H */
