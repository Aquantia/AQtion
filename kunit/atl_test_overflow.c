// SPDX-License-Identifier: GPL-2.0-only
/* Atlantic Network Driver unit test
 * Copyright (C) 2020 Marvell International Ltd.
 */

#include "kunit/test.h"

#include "aq_nic.h"
#include "hw_atl/hw_atl_b0.h"
#include "hw_atl2/hw_atl2.h"

#include "atl_fake_hw.h"

struct atl_test_context {
	struct aq_nic_s *aq_nic;

	struct fake_hw *fake_hw;
};

static void atl_test_overflow_min_rate_only(struct kunit *test,
					    const unsigned int link_mbps,
					    const unsigned int num_tcs,
					    const u32 min_rate[])
{
	struct atl_test_context *ctx = test->priv;
	struct aq_nic_s *nic = ctx->aq_nic;
	struct aq_hw_s *hw = nic->aq_hw;
	char buf[256];
	int err;
	int tc;

	KUNIT_ASSERT_GT(test, num_tcs, 0U);

	sprintf(buf, "%d", min_rate[0]);
	for (tc = 1; tc != num_tcs; tc++)
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ", %d",
			 min_rate[tc]);
	kunit_info(test, "%s(link_mbps=%u, num_tcs=%u, min_rate={ %s })",
		   __func__, link_mbps, num_tcs, buf);

	hw->aq_link_status.mbps = link_mbps;
	nic->aq_nic_cfg.tc_mode = num_tcs > 4 ? AQ_TC_MODE_8TCS :
						AQ_TC_MODE_4TCS;
	nic->aq_nic_cfg.tcs = num_tcs;

	for (tc = 0; tc != num_tcs; tc++) {
		err = aq_nic_setup_tc_min_rate(nic, tc, min_rate[tc]);
		KUNIT_ASSERT_EQ(test, err, 0);
	}

	nic->aq_hw_ops->hw_tc_rate_limit_set(hw);
	KUNIT_ASSERT_EQ(test, err, 0);

	kunit_info(test, "%s(link_mbps=%u, num_tcs=%u, min_rate={ %s }) %s",
		   __func__, link_mbps, num_tcs, buf, "PASSED");
}

static void atl_test_overflow_100m_1tc_min_rate(struct kunit *test)
{
	const unsigned int link_mbps = 100;
	const unsigned int num_tcs = 1;
	u32 tc_mbps[AQ_CFG_TCS_MAX];

	tc_mbps[0] = 0;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 20;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 101;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);
}

static void atl_test_overflow_100m_2tc_min_rate(struct kunit *test)
{
	const unsigned int link_mbps = 100;
	const unsigned int num_tcs = 2;
	u32 tc_mbps[AQ_CFG_TCS_MAX];

	tc_mbps[0] = 20;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 50;
	tc_mbps[1] = 50;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 101;
	tc_mbps[1] = 101;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);
}

static void atl_test_overflow_100m_4tc_min_rate(struct kunit *test)
{
	const unsigned int link_mbps = 100;
	const unsigned int num_tcs = 4;
	u32 tc_mbps[AQ_CFG_TCS_MAX];

	tc_mbps[0] = 20;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 20;
	tc_mbps[1] = 20;
	tc_mbps[2] = 20;
	tc_mbps[3] = 20;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 101;
	tc_mbps[1] = 101;
	tc_mbps[2] = 101;
	tc_mbps[3] = 101;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);
}

static void atl_test_overflow_1g_1tc_min_rate(struct kunit *test)
{
	const unsigned int link_mbps = 1000;
	const unsigned int num_tcs = 1;
	u32 tc_mbps[AQ_CFG_TCS_MAX];

	tc_mbps[0] = 0;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 100;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 200;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 400;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 600;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);

	tc_mbps[0] = 800;
	atl_test_overflow_min_rate_only(test, link_mbps, num_tcs, tc_mbps);
}

static struct kunit_case atl_test_overflow_cases[] = {
	KUNIT_CASE(atl_test_overflow_100m_1tc_min_rate),
	KUNIT_CASE(atl_test_overflow_100m_2tc_min_rate),
	KUNIT_CASE(atl_test_overflow_100m_4tc_min_rate),
	KUNIT_CASE(atl_test_overflow_1g_1tc_min_rate),
	{}
};

static void *atl_test_overflow_init_common(struct kunit *test)
{
	struct atl_test_context *ctx;

	kunit_info(test, "initializing\n");

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ctx->aq_nic = kunit_kzalloc(test, sizeof(*ctx->aq_nic), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->aq_nic);
	ctx->aq_nic->aq_nic_cfg.is_qos = true;

	ctx->aq_nic->aq_hw = kunit_kzalloc(test, sizeof(*ctx->aq_nic->aq_hw),
					   GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->aq_nic->aq_hw);
	ctx->aq_nic->aq_hw->aq_nic_cfg = &ctx->aq_nic->aq_nic_cfg;

	ctx->fake_hw = kunit_kzalloc(test, sizeof(*ctx->fake_hw), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx->fake_hw);
	fake_hw_init(ctx->fake_hw, test);

	test->priv = ctx;

	return ctx;
}

static int atl_test_overflow_init_a1(struct kunit *test)
{
	struct atl_test_context *ctx;

	ctx = atl_test_overflow_init_common(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ctx->aq_nic->aq_nic_cfg.aq_hw_caps = &hw_atl_b0_caps_aqc107;
	ctx->aq_nic->aq_hw->chip_features = ATL_HW_CHIP_ATLANTIC;
	ctx->aq_nic->aq_hw_ops = &hw_atl_ops_b0;

	return 0;
}

static int atl_test_overflow_init_a2(struct kunit *test)
{
	struct atl_test_context *ctx;

	ctx = atl_test_overflow_init_common(test);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ctx->aq_nic->aq_nic_cfg.aq_hw_caps = &hw_atl2_caps_aqc113;
	ctx->aq_nic->aq_hw->chip_features = ATL_HW_CHIP_ANTIGUA;
	ctx->aq_nic->aq_hw_ops = &hw_atl2_ops;

	return 0;
}

static void atl_test_overflow_exit(struct kunit *test)
{
	struct atl_test_context *ctx = test->priv;

	fake_hw_cleanup(ctx->fake_hw);
}

static struct kunit_suite atl_test_overflow_a1_suite = {
	.name = "atl_test_overflow_a1",
	.init = atl_test_overflow_init_a1,
	.exit = atl_test_overflow_exit,
	.test_cases = atl_test_overflow_cases,
};

static struct kunit_suite atl_test_overflow_a2_suite = {
	.name = "atl_test_overflow_a2",
	.init = atl_test_overflow_init_a2,
	.exit = atl_test_overflow_exit,
	.test_cases = atl_test_overflow_cases,
};

kunit_test_suites(&atl_test_overflow_a1_suite, &atl_test_overflow_a2_suite);

MODULE_LICENSE("GPL v2");
