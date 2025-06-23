/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stdint.h>

#include "config/interface/config_store.h"
#include "crc32_discovery.h"

bool crc32_armv8a_hw_available(void)
{
	uint32_t value = 0;

	if (!config_store_query(CONFIG_CLASSIFIER_HW_FEATURE, "crc32", 0, &value, sizeof(value)))
		return false;

	return value != 0;
}
