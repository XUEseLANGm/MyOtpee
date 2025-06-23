// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include <stdint.h>
#include "mock_ffa_internal_api.h"

TEST_GROUP(mock_ffa_internal_api)
{
	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().clear();
	}
};

TEST(mock_ffa_internal_api, ffa_svc)
{
	const uint64_t a0 = 0x0123456789abcdefULL;
	const uint64_t a1 = 0x123456789abcdef0ULL;
	const uint64_t a2 = 0x23456789abcdef01ULL;
	const uint64_t a3 = 0x3456789abcdef012ULL;
	const uint64_t a4 = 0x456789abcdef0123ULL;
	const uint64_t a5 = 0x56789abcdef01234ULL;
	const uint64_t a6 = 0x6789abcdef012345ULL;
	const uint64_t a7 = 0x789abcdef0123456ULL;
	const struct ffa_params expect_result = {
		a7, a6, a5, a4, a3, a2, a1, a0
	};
	struct ffa_params result = { 0 };

	expect_ffa_svc(a0, a1, a2, a3, a4, a5, a6, a7, &expect_result);
	ffa_svc(a0, a1, a2, a3, a4, a5, a6, a7, &result);

	MEMCMP_EQUAL(&expect_result, &result, sizeof(result));
}
