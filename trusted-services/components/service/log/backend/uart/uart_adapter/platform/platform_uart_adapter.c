/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <platform/interface/uart.h>
#include <psa/error.h>
#include <service/log/backend/uart/uart_adapter/uart_adapter.h>
#include <stddef.h>

/*
 * Setup function to a platform uart driver.  The actual realization of the driver
 * will depend on the platform selected at build-time.
 */
static struct platform_uart_driver driver = { 0 };

int uart_adapter_init(int instance)
{
	return platform_uart_create(&driver, instance);
}

/*
 * Deallocate the uart interface.
 */
void uart_adapter_deinit(void)
{
	platform_uart_destroy(&driver);
}

/*
 * Send string to uart interface for printing.
 */
void uart_hardware_puts(const char *msg)
{
	int i = 0;

	while (msg[i] != '\0') {
		driver.iface->uart_putc(driver.context, (uint8_t)msg[i]);
		i++;
	}
}

/*
 * Flush the UART.
 */
void uart_hardware_flush(void)
{
	driver.iface->uart_flush(driver.context);
}
