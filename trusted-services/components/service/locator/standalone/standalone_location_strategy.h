/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_LOCATION_STRATEGY_H
#define STANDALONE_LOCATION_STRATEGY_H

#include <service_locator.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns a service_location_strategy for locating a service instance
 * from a bundle of standalone service instances that are part of the
 * client execution context.
 */
const struct service_location_strategy *standalone_location_strategy(void);

#ifdef __cplusplus
}
#endif

#endif /* STANDALONE_LOCATION_STRATEGY_H */