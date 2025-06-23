/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ENDIAN_LE_H
#define ENDIAN_LE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Functions for loading and storing integer values as unaligned
 * values in Little Endian byte order.  The address to load or
 * store the value is specified by a base address and an offset
 * to facilitate unaligned structure access.
 */
uint8_t  load_u8_le(const void *base, size_t offset);
uint16_t load_u16_le(const void *base, size_t offset);
uint32_t load_u32_le(const void *base, size_t offset);
uint64_t load_u64_le(const void *base, size_t offset);

void store_u8_le(void *base, size_t offset, uint8_t val);
void store_u16_le(void *base, size_t offset, uint16_t val);
void store_u32_le(void *base, size_t offset, uint32_t val);
void store_u64_le(void *base, size_t offset, uint64_t val);

#ifdef __cplusplus
}
#endif

#endif /* ENDIAN_LE_H */
