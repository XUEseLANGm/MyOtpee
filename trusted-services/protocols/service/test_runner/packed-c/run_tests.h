/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_TEST_RUNNER_RUN_TESTS
#define TS_TEST_RUNNER_RUN_TESTS

/**
 * Input parmeters consist of test spec (defined in test_spec.h) to
 * define the set of tests to run.
 */
#include "test_spec.h"

/* Output parameters consist of a test summary followed
 * by a setof [0..*] variable length test result records.
 * Each test result has a fixed size structure followed
 * by variable length parameters that specify the test
 * name and group.
 */
#include "test_result.h"

#endif /* TS_TEST_RUNNER_RUN_TESTS */
