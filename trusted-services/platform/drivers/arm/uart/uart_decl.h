/*
 * Copyright (c) 2017-2023, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This is a modified version of the uart platform driver from trusted-firmware-a.
 * The code has been modified to allow the peripheral to be accessed by S-EL0 at
 * an arbitrary virtual address.
 */

#ifndef UART_DECL_H
#define UART_DECL_H

#include <stdint.h>

int uart_deinit(uintptr_t addr);
int uart_init(uintptr_t addr);
void uflush(uintptr_t addr);
void uputc(uint8_t ch, uintptr_t addr);

#endif /* UART_DECL_H */
