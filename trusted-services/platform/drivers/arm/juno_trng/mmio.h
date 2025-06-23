/*
 * Copyright (c) 2013-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copied from trustedfirmware-a and stripped down to only provide functions
 * used by juno_trng.c.
 */

#ifndef MMIO_H
#define MMIO_H

#include <stdint.h>


static inline void mmio_write_32(uintptr_t addr, uint32_t value)
{
	*(volatile uint32_t*)addr = value;
}

static inline uint32_t mmio_read_32(uintptr_t addr)
{
	return *(volatile uint32_t*)addr;
}

#endif /* MMIO_H */
