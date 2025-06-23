/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <service/test_runner/provider/backend/simple_c/simple_c_test_runner.h>
#include <stdbool.h>
#include <string.h>

/* Mock test test functions */
static bool test_that_passes(struct test_failure *failure)
{
    (void)failure;
    return true;
}

static bool test_that_fails(struct test_failure *failure)
{
    failure->line_num = __LINE__;
    failure->info = 27;
    return false;
}

/**
 * The mock backend is a test_runner that provides some mock test cases
 * that can be used for testing the test_runner service iteslf.  It uses
 * the simple_c test runner.
 */
const struct simple_c_test_case platform_tests[] = {
    {.name = "Trng", .test_func = test_that_passes},
    {.name = "CheckIOmap", .test_func = test_that_passes}
};

const struct simple_c_test_group platform_test_group =
{
    .group = "PlatformTests",
    .num_test_cases = sizeof(platform_tests)/sizeof(struct simple_c_test_case),
    .test_cases = platform_tests
};

const struct simple_c_test_case config_tests[] = {
    {.name = "ValidateConfig", .test_func = test_that_fails},
    {.name = "ApplyConfig", .test_func = test_that_passes}
};

const struct simple_c_test_group config_test_group =
{
    .group = "ConfigTests",
    .num_test_cases = sizeof(config_tests)/sizeof(struct simple_c_test_case),
    .test_cases = config_tests
};



void test_runner_register_default_backend(struct test_runner_provider *context)
{
    simple_c_test_runner_init(context);

    simple_c_test_runner_register_group(&platform_test_group);
    simple_c_test_runner_register_group(&config_test_group);
}