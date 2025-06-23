/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#ifndef LIBSP_TEST_MOCK_ASSERT_H_
#define LIBSP_TEST_MOCK_ASSERT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <setjmp.h>

typedef jmp_buf assert_environment_t;

/*
 * SETUP_ASSERT_ENVIRONMENT
 * Both expect_assert and setjmp must be called without putting them into a new
 * function. The only way is to use an operator between them. Logical operators
 * would introduce branches which could introduce uncovered branches. The
 * solution is use arithmetic operators. expect_assert always return 0 so the
 * value of the sum is determined by the setjmp return value.
 *
 * Example usage:
 * assert_environment_t env;
 *
 * if (SETUP_ASSERT_ENVIRONMENT(env) {
 *     function_with_assert_fail();
 * }
 */
#define SETUP_ASSERT_ENVIRONMENT(env) (expect_assert(&env) + (setjmp(env) == 0))

int expect_assert(assert_environment_t *env);

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_TEST_MOCK_ASSERT_H_ */
