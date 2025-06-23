/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_PLATFORM_INTERFACE_UART_H
#define TS_PLATFORM_INTERFACE_UART_H

/*
 * Interface definintion for a platform uart driver.  A platform provider will
 * provide concrete implementations of this interface for each alternative
 * implementation supported.
 */
#include <stddef.h>

#include "device_region.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A platform uart driver context.
 */
typedef struct {
	/* Base address of the driver instance */
	uintptr_t base_address;
} platform_uart_context;

/*
 * Virtual interface for a platform uart driver.  A platform will provide
 * one or more concrete implementations of this interface.
 */
struct platform_uart_iface {
	/**
	 * \brief Putc to submit a character to platform uart
	 * *
	 * * \param context     Platform driver context
	 * \param ch	         Character to be written to UART
	 *
	 * \return            0 if successful.
	 */
	int (*uart_putc)(platform_uart_context *context, uint8_t ch);
	/**
	 * \brief Wait for empty input FIFO in platform uart
	 *
	 * * \param context     Platform driver context
	 * *
	 * \return            0 if successful.
	 */
	int (*uart_flush)(platform_uart_context *context);
};

/*
 * A platform uart driver instance.
 */
struct platform_uart_driver {
	void *context; /**< Opaque driver context */
	const struct platform_uart_iface *iface; /**< Interface methods */
};

/**
 * \brief Factory method to construct a platform specific uart driver
 *
 * \param driver    Pointer to driver structure to initialize on construction.
 * \param instance    Deployment specific uart instance.
 *
 * \return          0 if successful.
 */
int platform_uart_create(struct platform_uart_driver *driver, int instance);

/**
 * \brief Destroy a driver constructed using the factory method
 *
 * \param driver    Pointer to driver structure for constructed driver.
 */
void platform_uart_destroy(struct platform_uart_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* TS_PLATFORM_INTERFACE_UART_H */
