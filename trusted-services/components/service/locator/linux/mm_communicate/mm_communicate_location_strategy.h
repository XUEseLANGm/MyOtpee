/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MM_COMMUNICATE_LOCATION_STRATEGY_H
#define MM_COMMUNICATE_LOCATION_STRATEGY_H

#include <service_locator.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns a service_location_strategy for locating a service instance
 * hosted in a secure partition, accessed using MM Communicate from Linux userspace.
 * Relies on an FFA Linux kernel driver.
 */
const struct service_location_strategy *mm_communicate_location_strategy(void);

#ifdef __cplusplus
}
#endif

#endif /* MM_COMMUNICATE_LOCATION_STRATEGY_H */
