// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 */

#include <linux/kernel.h>

#include "kunit/test.h"

#include "atl_fake_hw.h"
#include "atl_fake_hw_regs.h"

static __thread struct fake_hw *g_fake_hw;

struct fake_hw_priv {
	struct fake_hw_func {
		void *func;
		unsigned int times;
	} called[256];
	unsigned int cnt_calls;

	struct rhashtable register_ht;
};

static int func_call_index(void *func)
{
	struct fake_hw_priv *priv = g_fake_hw->priv;
	int i;

	for (i = 0; i != priv->cnt_calls; i++)
		if (priv->called[i].func == func)
			return i;

	return -1;
}

static struct fake_hw_func *find_or_add_func(void *func)
{
	int idx = func_call_index(func);
	struct fake_hw_priv *priv = g_fake_hw->priv;

	if (idx == -1) {
		idx = priv->cnt_calls++;
		priv->called[idx].func = func;
	}

	return &priv->called[idx];
}

static void trace_func_call(void *func)
{
	struct fake_hw_func *func_call = find_or_add_func(func);

	KUNIT_EXPECT_NOT_ERR_OR_NULL(g_fake_hw->test, func_call);
	func_call->times++;
}

static u32 width_from_mask_shift(struct fake_hw *this, const u32 msk,
				 const u32 shift)
{
	const u32 max_value = msk >> shift;

	KUNIT_ASSERT_TRUE_MSG(this->test, is_power_of_2(max_value + 1),
			      "\tIncorrect mask: expected all enabled (1) bits to be grouped together.\n"
			      "\tActual: msk=0x%X, shift=%u => max_value=%u",
			      msk, shift, max_value);

	return order_base_2(max_value + 1);
}

static void fake_hw_write_reg_bit(struct atl_hw *parent, struct aq_hw_s *hw,
				  const u32 addr, const u32 msk,
				  const u32 shift, const u32 val)
{
	struct fake_hw *this = container_of(parent, struct fake_hw, parent);
	const u32 width = width_from_mask_shift(this, msk, shift);
	const u32 max_value = BIT(width) - 1;
	struct atl_register_ht_key ht_key = {
		.addr = addr,
		.shift = shift,
		.width = width,
	};
	struct atl_register_ht_entry ht_entry = {
		.key = ht_key,
		.value = val,
	};
	int err;

#define FAKE_HW_ASSERT_MSG_FMT "\tin %s(addr=0x%08X, msk=0x%X, shift=%u, val=%u)"
#define FAKE_HW_ASSERT_MSG_ARGS "write_reg_bit", addr, msk, shift, val

	KUNIT_ASSERT_LE_MSG(this->test, val, max_value,
			    FAKE_HW_ASSERT_MSG_FMT, FAKE_HW_ASSERT_MSG_ARGS);

	err = atl_register_ht_insert(&this->priv->register_ht, &ht_entry);
	KUNIT_ASSERT_EQ_MSG(this->test, err, 0, "\tInternal error: %s",
			    "hash table insert failed");

#undef FAKE_HW_ASSERT_MSG_FMT
#undef FAKE_HW_ASSERT_MSG_ARGS
}

void FAKE_HW_FUNC_NAME(aq_hw_write_reg_bit)(struct aq_hw_s *hw, u32 addr,
					    u32 msk, u32 shift, u32 val)
{
	struct atl_hw *parent = &g_fake_hw->parent;

	trace_func_call(FAKE_HW_FUNC_NAME(aq_hw_write_reg_bit));

	return parent->write_reg_bit(parent, hw, addr, msk, shift, val);
}

static u32 fake_hw_read_reg_bit(struct atl_hw *parent, struct aq_hw_s *hw,
				u32 addr, u32 msk, u32 shift)
{
	struct fake_hw *this = container_of(parent, struct fake_hw, parent);
	const u32 width = width_from_mask_shift(this, msk, shift);
	struct atl_register_ht_key ht_key = {
		.addr = addr,
		.shift = shift,
		.width = width,
	};
	struct atl_register_ht_entry *entry;

	entry = atl_register_ht_lookup(&this->priv->register_ht, &ht_key);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(this->test, entry);

	return entry->value;
}

u32 FAKE_HW_FUNC_NAME(aq_hw_read_reg_bit)(struct aq_hw_s *hw, u32 addr, u32 msk,
					  u32 shift)
{
	struct atl_hw *parent = &g_fake_hw->parent;

	trace_func_call(FAKE_HW_FUNC_NAME(aq_hw_read_reg_bit));

	return parent->read_reg_bit(parent, hw, addr, msk, shift);
}

static u32 fake_hw_read_reg(struct atl_hw *parent, struct aq_hw_s *hw, u32 reg)
{
	struct fake_hw *this = container_of(parent, struct fake_hw, parent);

	KUNIT_FAIL(this->test, "%s not implemented", "read_reg");

	return 0;
}

u32 FAKE_HW_FUNC_NAME(aq_hw_read_reg)(struct aq_hw_s *hw, u32 reg)
{
	struct atl_hw *parent = &g_fake_hw->parent;

	trace_func_call(FAKE_HW_FUNC_NAME(aq_hw_read_reg));

	return parent->read_reg(parent, hw, reg);
}

static void fake_hw_write_reg(struct atl_hw *parent, struct aq_hw_s *hw,
			      u32 reg, u32 value)
{
	struct fake_hw *this = container_of(parent, struct fake_hw, parent);

	KUNIT_FAIL(this->test, "%s not implemented", "write_reg");
}

void FAKE_HW_FUNC_NAME(aq_hw_write_reg)(struct aq_hw_s *hw, u32 reg, u32 value)
{
	struct atl_hw *parent = &g_fake_hw->parent;

	trace_func_call(FAKE_HW_FUNC_NAME(aq_hw_write_reg));

	return parent->write_reg(parent, hw, reg, value);
}

static u64 fake_hw_read_reg64(struct atl_hw *parent, struct aq_hw_s *hw,
			      u32 reg)
{
	struct fake_hw *this = container_of(parent, struct fake_hw, parent);

	KUNIT_FAIL(this->test, "%s not implemented", "read_reg64");

	return 0;
}

u64 FAKE_HW_FUNC_NAME(aq_hw_read_reg64)(struct aq_hw_s *hw, u32 reg)
{
	struct atl_hw *parent = &g_fake_hw->parent;

	trace_func_call(FAKE_HW_FUNC_NAME(aq_hw_read_reg64));

	return parent->read_reg64(parent, hw, reg);
}

static int fake_hw_err_from_flags(struct atl_hw *parent, struct aq_hw_s *hw)
{
//	struct fake_hw *this = container_of(parent, struct fake_hw, parent);

	return 0;
}

int FAKE_HW_FUNC_NAME(aq_hw_err_from_flags)(struct aq_hw_s *hw)
{
	struct atl_hw *parent = &g_fake_hw->parent;

	trace_func_call(FAKE_HW_FUNC_NAME(aq_hw_err_from_flags));

	return parent->err_from_flags(parent, hw);
}

static void fake_hw_expect_called(void *func)
{
	const struct fake_hw_func *func_call = find_or_add_func(func);

	KUNIT_ASSERT_NE(g_fake_hw->test, func_call->times, 0U);
}

static void fake_hw_expect_called_n_times(void *func,
					  const unsigned int n_times)
{
	const struct fake_hw_func *func_call = find_or_add_func(func);

	KUNIT_ASSERT_EQ(g_fake_hw->test, func_call->times, n_times);
}

void fake_hw_init(struct fake_hw *this, struct kunit *test)
{
	int err;

	this->parent.write_reg_bit = fake_hw_write_reg_bit;
	this->parent.read_reg_bit = fake_hw_read_reg_bit;
	this->parent.read_reg = fake_hw_read_reg;
	this->parent.write_reg = fake_hw_write_reg;
	this->parent.read_reg64 = fake_hw_read_reg64;
	this->parent.err_from_flags = fake_hw_err_from_flags;

	this->test = test;

	this->priv = kunit_kzalloc(test, sizeof(*this->priv), GFP_KERNEL);

	this->expect_called = fake_hw_expect_called;
	this->expect_called_n_times = fake_hw_expect_called_n_times;

	err = atl_register_ht_init(&this->priv->register_ht);
	KUNIT_ASSERT_EQ(test, err, 0);

	g_fake_hw = this;

	kunit_warn(test, "%s: fake_hw=0x%llx", __func__, (uint64_t)this);
}

void fake_hw_cleanup(struct fake_hw *this)
{
	kunit_warn(this->test, "%s: fake_hw=0x%llx", __func__, (uint64_t)this);

	atl_register_ht_destroy(&this->priv->register_ht);

	KUNIT_ASSERT_PTR_EQ(this->test, g_fake_hw, this);
	g_fake_hw = NULL;
}
