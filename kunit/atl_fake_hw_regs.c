// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 */

#include "atl_fake_hw_regs.h"

#include "linux/rhashtable.h"
#include "kunit/test.h"

static const struct rhashtable_params register_ht_params = {
	.head_offset = offsetof(struct atl_register_ht_entry, rhash_node),
	.key_offset = offsetof(struct atl_register_ht_entry, key),
	.key_len = sizeof(struct atl_register_ht_key),
	.automatic_shrinking = true,
};

int atl_register_ht_init(struct rhashtable *reg_ht)
{
	return rhashtable_init(reg_ht, &register_ht_params);
}

void atl_register_ht_destroy(struct rhashtable *reg_ht)
{
	rhashtable_destroy(reg_ht);
}

int atl_register_ht_insert(struct rhashtable *reg_ht,
			   struct atl_register_ht_entry *new_entry)
{
	struct atl_register_ht_entry *entry;

	entry = atl_register_ht_lookup(reg_ht, &new_entry->key);
	if (entry) {
		entry->value = new_entry->value;
		return 0;
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(&entry->key, &new_entry->key, sizeof(entry->key));
	entry->value = new_entry->value;

	return rhashtable_insert_fast(reg_ht, &entry->rhash_node,
				      register_ht_params);
}

struct atl_register_ht_entry *
atl_register_ht_lookup(struct rhashtable *reg_ht,
		       struct atl_register_ht_key *key)
{
	return rhashtable_lookup_fast(reg_ht, key, register_ht_params);
}
