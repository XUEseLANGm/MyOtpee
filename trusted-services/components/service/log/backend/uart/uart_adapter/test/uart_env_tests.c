/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <service/log/backend/uart/uart_adapter/uart_adapter.h>
#include <service/test_runner/provider/backend/simple_c/simple_c_test_runner.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static bool check_uart(struct test_failure *failure)
{
	int status = uart_adapter_init(0);

	failure->info = status;

	if (status != 0)
		return false;

	uart_hardware_puts("XXXXXXXXXXXXXXXXXXX\0");

	uart_hardware_flush();

	return true;
}

/**
 * Define an register test group
 */
void uart_env_tests_register(void)
{
	static const struct simple_c_test_case uart_env_tests[] = { { .name = "UartChkFlush",
								      .test_func = check_uart } };

	static const struct simple_c_test_group uart_env_test_group = {
		.group = "UartEnvTests",
		.num_test_cases = sizeof(uart_env_tests) / sizeof(struct simple_c_test_case),
		.test_cases = uart_env_tests
	};

	simple_c_test_runner_register_group(&uart_env_test_group);
}
