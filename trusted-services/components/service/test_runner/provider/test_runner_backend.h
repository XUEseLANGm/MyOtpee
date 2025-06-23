/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEST_RUNNER_BACKEND_H
#define TEST_RUNNER_BACKEND_H

#include <stddef.h>
#include <service/test_runner/common/test_runner.h>

#ifdef __cplusplus
extern "C" {
#endif

struct test_runner_provider;

/**
 * Provides an abstract interface for a backend test runner. A
 * concrete implementation will map methods to a test framework
 * such as CppUtets.  test_runner objects may be linked to
 * accommodate a mix of backend test frameworks.
 */
struct test_runner_backend
{
	/* Return the number of tests that are qualified by the test spec */
	size_t (*count_tests)(const struct test_spec *spec);

	/* Run a set of tests according to the provided test_spec */
	int (*run_tests)(const struct test_spec *spec,
		struct test_summary *summary, struct test_result *results, size_t result_limit);

	/* List a set of tests according to the provided test_spec */
	void (*list_tests)(const struct test_spec *spec,
		struct test_summary *summary, struct test_result *results, size_t result_limit);

	/* Used by the test_runner_provider to maintain a linked list */
	struct test_runner_backend *next;
};

/**
 * A concrete test_runner may provide an implementation of this function if it
 * is to be the default test runner for a deployment.  Additional test runners
 * may be registered but there can only be one default for a deployment.
 */
void test_runner_register_default_backend(struct test_runner_provider *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TEST_RUNNER_BACKEND_H */
