/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CRC32_DISCOVERY_H
#define CRC32_DISCOVERY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool crc32_armv8a_hw_available(void);

#ifdef __cplusplus
}
#endif

#endif /* CRC32_DISCOVERY_H */
