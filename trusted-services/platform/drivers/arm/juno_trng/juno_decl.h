/*
 * Copyright (c) 2017-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This is a modified version of the juno trng platform driver from trusted-firmware-a.
 * The code has been modified to allow the peripheral to be accessed by S-EL0 at
 * an arbitrary virtual address.
 */

#ifndef JUNO_DECL_H
#define JUNO_DECL_H

#include <stdint.h>

void juno_trng_set_base_addr(uintptr_t addr);
int juno_getentropy(void *buf, size_t len);

#endif /* JUNO_DECL_H */
