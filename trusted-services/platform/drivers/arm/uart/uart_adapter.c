/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <assert.h>
#include <config/interface/config_store.h>
#include <platform/interface/device_region.h>
#include <platform/interface/uart.h>
#include <psa/error.h>
#include <stdlib.h>

#include "uart_decl.h"

/*
 * Flush the UART
 */
static int uart_flush(platform_uart_context *context)
{
	uflush(context->base_address);

	return 0;
}

/*
 * Send character to UART
 */
static int uart_putc(platform_uart_context *context, uint8_t ch)
{
	uputc(ch, context->base_address);

	return 0;
}

/*
 * Initialize the driver for the UART
 */
int platform_uart_create(struct platform_uart_driver *driver, int instance)
{
	static const struct platform_uart_iface iface = { .uart_flush = uart_flush,
							  .uart_putc = uart_putc };

	struct device_region device_region;

	if (!config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION, "uart", instance, &device_region,
				sizeof(device_region)))
		return PSA_STATUS_HARDWARE_FAILURE;

	driver->context = malloc(sizeof(platform_uart_context));

	if (driver->context) {
		/* Set only if context was created */
		driver->iface = &iface;

		/* A device region has been provided, possibly from an external configuration. */
		((platform_uart_context *)driver->context)->base_address = device_region.base_addr;

		return uart_init(device_region.base_addr);
	}

	return -1;
}

void platform_uart_destroy(struct platform_uart_driver *driver)
{
	if (driver->context) {
		uart_deinit(((platform_uart_context *) driver->context)->base_address);
		free(driver->context);
		driver->context = NULL;
	}

	driver->iface = NULL;
}
