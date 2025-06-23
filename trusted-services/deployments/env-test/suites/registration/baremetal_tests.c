// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 */

#include <config/test/sp/sp_config_tests.h>
#include <service/block_storage/block_store/device/semihosting/test/sh_block_store_tests.h>
#include <service/crypto/backend/mbedcrypto/trng_adapter/test/trng_env_tests.h>
#include <service/log/backend/uart/uart_adapter/test/uart_env_tests.h>
#include <service/test_runner/provider/backend/simple_c/simple_c_test_runner.h>

/**
 * Register tests that constitute the 'baremetal-tests' suite. Used for testing
 * platform drivers that conform to the 'baremetal' driver model.
 */
void env_test_register_tests(struct test_runner_provider *context)
{
	simple_c_test_runner_init(context);

	sp_config_tests_register();
	trng_env_tests_register();
	sh_block_store_tests_register();
	uart_env_tests_register();
}
