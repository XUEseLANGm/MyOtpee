// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */

#include "fdt_helpers.h"

bool dt_get_u32(const void *fdt, int node, const char *prop_name, uint32_t *prop_val)
{
	const fdt32_t *u32_prop = NULL;
	int len = 0;

	if (!fdt || !prop_name || !prop_val)
		return false;

	u32_prop = fdt_getprop(fdt, node, prop_name, &len);
	if (!u32_prop || len != sizeof(*u32_prop))
		return false;

	*prop_val = fdt32_to_cpu(*u32_prop);

	return true;
}

bool dt_get_u64(const void *fdt, int node, const char *prop_name, uint64_t *prop_val)
{
	const fdt64_t *u64_prop = NULL;
	int len = 0;

	if (!fdt || !prop_name || !prop_val)
		return false;

	u64_prop = fdt_getprop(fdt, node, prop_name, &len);
	if (!u64_prop || len != sizeof(*u64_prop))
		return false;

	*prop_val = fdt64_to_cpu(*u64_prop);

	return true;
}

bool dt_get_u32_by_offset(const void *fdt, int offset, const char **prop_name, uint32_t *prop_val)
{
	const fdt32_t *u32_prop = NULL;
	int len = 0;

	if (!fdt || !prop_name || !prop_val)
		return false;

	u32_prop = fdt_getprop_by_offset(fdt, offset, prop_name, &len);
	if (!u32_prop || len != sizeof(*u32_prop) || !(*prop_name))
		return false;

	*prop_val = fdt32_to_cpu(*u32_prop);

	return true;
}

bool dt_get_u64_by_offset(const void *fdt, int offset, const char **prop_name, uint64_t *prop_val)
{
	const fdt64_t *u64_prop = NULL;
	int len = 0;

	if (!fdt || !prop_name || !prop_val)
		return false;

	u64_prop = fdt_getprop_by_offset(fdt, offset, prop_name, &len);
	if (!u64_prop || len != sizeof(*u64_prop) || !(*prop_name))
		return false;

	*prop_val = fdt64_to_cpu(*u64_prop);

	return true;
}
