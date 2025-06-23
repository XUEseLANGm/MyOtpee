/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_TEST_RUNNER_TEST_SPEC
#define TS_TEST_RUNNER_TEST_SPEC

/**
 * Variable length parameters used to specify a test or
 * group of tests.  A missing parameter is interpreted
 * as a wildcard.
 */
enum
{
    /* Specifies the name of a particular test to run.
     * The parameter should consist of an ascii string
     * without a zero terminator.
     */
    TS_TEST_RUNNER_TEST_SPEC_TAG_NAME = 1,

    /* Specifies a group of tests to run.
     * The parameter should consist of an ascii string
     * without a zero terminator.
     */
    TS_TEST_RUNNER_TEST_SPEC_TAG_GROUP = 2
};

#endif /* TS_TEST_RUNNER_TEST_SPEC */
