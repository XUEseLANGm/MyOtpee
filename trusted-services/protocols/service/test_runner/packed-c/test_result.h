/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_TEST_RUNNER_TEST_RESULT
#define TS_TEST_RUNNER_TEST_RESULT

#include <stdint.h>

/**
 * Test result summary structure
 */
struct __attribute__ ((__packed__)) ts_test_runner_result_summary
{
  uint32_t num_tests;
  uint32_t num_passed;
  uint32_t num_failed;
};

/**
 * Variable length parameter tag for a test result object.
 * Multiple test results may be returned for a test run.
 */
enum
{
    /* A test result record describes the result of a
     * particular test.
     */
    TS_TEST_RUNNER_TEST_RESULT_TAG = 1
};

/* Test run state values */
enum
{
    TS_TEST_RUNNER_TEST_RESULT_RUN_STATE_NOT_RUN = 1,
    TS_TEST_RUNNER_TEST_RESULT_RUN_STATE_PASSED = 2,
    TS_TEST_RUNNER_TEST_RESULT_RUN_STATE_FAILED = 3
};

/* Test result fixed sized structure */
struct __attribute__ ((__packed__)) ts_test_runner_test_result
{
  uint32_t run_state;
};

/* Variable length output parameter tags */
enum
{
    /* The name of the test */
    TS_TEST_RUNNER_TEST_RESULT_TAG_NAME = 1,

    /* The group the test belongs to */
    TS_TEST_RUNNER_TEST_RESULT_TAG_GROUP = 2,

    /* Test failure recorded, optionally included on failure */
    TS_TEST_RUNNER_TEST_RESULT_TAG_FAILURE = 3
};

/* Test failure fixed sized structure */
struct __attribute__ ((__packed__)) ts_test_runner_test_failure
{
  uint32_t line_num;
  uint64_t info;
};


#endif /* TS_TEST_RUNNER_TEST_RESULT */
