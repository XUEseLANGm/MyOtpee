// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */

#include <service/test_runner/provider/backend/simple_c/simple_c_test_runner.h>
#include <config/test/sp/sp_config_tests.h>

/**
 * Register tests that constitute the 'edk2-platform-tests' suite. Used for testing
 * platform drivers that conform to the 'edk2 (UEFI)' driver model.
 */
void env_test_register_tests(struct test_runner_provider *context)
{
	simple_c_test_runner_init(context);

	sp_config_tests_register();
}
