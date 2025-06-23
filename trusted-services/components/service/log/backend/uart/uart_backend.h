/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef UART_BACKEND_H
#define UART_BACKEND_H

#include <service/log/backend/log_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize the UART based backend
 *
 * Initializes an UART backend that uses the interface provided by the
 * UART adapter to execute UART operations.
 *
 * \param[in] uart_instance_num  The UART hardware instance number to use
 *
 * \return PSA_SUCCESS if backend initialized successfully
 */
struct log_backend *uart_backend_init(int uart_instance_num);

/**
 * \brief Clean-up to free any resource used by the backend
 */
void uart_backend_deinit(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* UART_BACKEND_H */
