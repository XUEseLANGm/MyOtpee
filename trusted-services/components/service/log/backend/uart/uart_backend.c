/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/log/backend/log_backend.h>
#include <service/log/backend/uart/uart_adapter/uart_adapter.h>
#include <stddef.h>

static log_status_t uart_puts(void *context, const char *str)
{
	(void)context;
	uart_hardware_puts(str);

	return LOG_STATUS_SUCCESS;
}

struct log_backend *uart_backend_init(int uart_instance_num)
{
	int status = 0;
	static struct log_backend backend = {0};
	static const struct log_backend_interface interface = { uart_puts };

	status = uart_adapter_init(uart_instance_num);

	if (status != 0)
		return NULL;

	backend.context = NULL;
	backend.interface = &interface;

	return &backend;
}

void uart_backend_deinit(void)
{
	uart_adapter_deinit();
}
