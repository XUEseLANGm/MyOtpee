/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <sys/auxv.h>

#include "crc32_discovery.h"

bool crc32_armv8a_hw_available(void)
{
	unsigned long hwcaps = getauxval(AT_HWCAP);
	return (hwcaps & HWCAP_CRC32) == HWCAP_CRC32;
}
