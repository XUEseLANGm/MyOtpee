// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#include "mock_assert.h"
#include <assert.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

int expect_assert(assert_environment_t *env)
{
	mock().expectOneCall("__assert_fail").andReturnValue(env);
	return 0;
}

void __assert_fail(const char *assertion, const char *file, unsigned int line,
		   const char *function)
{
	(void)assertion;
	(void)file;
	(void)line;
	(void)function;

	assert_environment_t *env = (assert_environment_t *)mock()
					    .actualCall("__assert_fail")
					    .returnPointerValue();
	longjmp(*env, 1);
}
