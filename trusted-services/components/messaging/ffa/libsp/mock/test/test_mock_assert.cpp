// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#include <assert.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include "mock_assert.h"

TEST_GROUP(mock_assert)
{
	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().clear();
	}
};

TEST(mock_assert, assert)
{
	assert_environment_t assert_env;

	if (SETUP_ASSERT_ENVIRONMENT(assert_env)) {
		assert(false);
		FAIL("Assert jump not happened"); // Should not be called
	}
}
