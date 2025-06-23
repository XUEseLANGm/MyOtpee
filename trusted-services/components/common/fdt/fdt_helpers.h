/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */

#include <libfdt.h>
#include <stdbool.h>

bool dt_get_u32(const void *fdt, int node, const char *prop_name, uint32_t *prop_val);
bool dt_get_u64(const void *fdt, int node, const char *prop_name, uint64_t *prop_val);
bool dt_get_u32_by_offset(const void *fdt, int offset, const char **prop_name, uint32_t *prop_val);
bool dt_get_u64_by_offset(const void *fdt, int offset, const char **prop_name, uint64_t *prop_val);
