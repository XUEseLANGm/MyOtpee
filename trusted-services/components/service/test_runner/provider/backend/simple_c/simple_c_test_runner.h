/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SIMPLE_C_TEST_RUNNER_H
#define SIMPLE_C_TEST_RUNNER_H

#include <service/test_runner/common/test_runner.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * A simple C code test runner.  Allows tests to be run in environments
 * where C++ and hence use of cpputest is not supported.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct test_runner_provider;

/**
 * Describes a test case.  Each test cases is a member of a test group.
 */
struct simple_c_test_case
{
	/* The test name string */
	const char *name;

	/* The test function that results true for a pass, false for a fail. */
	bool (*test_func)(struct test_failure *test_failure);
};

/**
 * Describes a test group consisting of [0..*] test cases.
 */
struct simple_c_test_group
{
	/* The test group string */
	const char *group;

	/* Number of test cases in the group */
	size_t num_test_cases;

	/* Pointer to an array of test cases */
	const struct simple_c_test_case *test_cases;
};

/**
 * Initialise the test runner and register it as a backend to the
 * test_runner_provider.  The simple_c test runner is a singleton.
 */
void simple_c_test_runner_init(struct test_runner_provider *frontend);

/**
 * Registers a test group with the test runner.
 */
void simple_c_test_runner_register_group(const struct simple_c_test_group *test_group);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIMPLE_C_TEST_RUNNER_H */
