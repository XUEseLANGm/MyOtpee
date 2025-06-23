/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef UART_ADAPTER_H
#define UART_ADAPTER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialise the uart adapter
 *
 * \param instance    Deployment specific uart instance.
 *
 * \return          0 if successful.
 */
int uart_adapter_init(int instance);

/**
 * \brief Cleans-up the uart adapter.
 */
void uart_adapter_deinit(void);

/**
 * \brief Sends character to uart driver.
 */
void uart_hardware_puts(const char *msg);

/**
 * \brief Sends flush to uart driver.
 */
void uart_hardware_flush(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* UART_ADAPTER_H */
