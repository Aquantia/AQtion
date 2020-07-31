/* SPDX-License-Identifier: GPL-2.0-only */
/* Atlantic Network Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 */

#ifndef ATL_FAKE_HW_REGS_H
#define ATL_FAKE_HW_REGS_H

#include "linux/types.h"
#include "linux/rhashtable-types.h"

struct atl_register_ht_key {
	u32 addr: 16;
	u32 shift: 5; // aka offset (0-31), each register is 32-bit wide
	u32 reserved1: 3;
	u32 width: 5;
};

struct atl_register_ht_entry {
	struct rhash_head rhash_node;
	struct atl_register_ht_key key;

	u32 value;
};

int atl_register_ht_init(struct rhashtable *reg_ht);
void atl_register_ht_destroy(struct rhashtable *reg_ht);

int atl_register_ht_insert(struct rhashtable *reg_ht,
			   struct atl_register_ht_entry *entry);
struct atl_register_ht_entry *
atl_register_ht_lookup(struct rhashtable *reg_ht,
		       struct atl_register_ht_key *key);

#endif /* ATL_FAKE_HW_REGS_H */
