/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SPFFA_LOCATION_STRATEGY_H
#define SPFFA_LOCATION_STRATEGY_H

#include <service_locator.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns a service_location_strategy for locating a service instance
 * hosted in a secure partition, accessed using FFA from another secure
 * partition.
 */
const struct service_location_strategy *sp_ts_location_strategy(void);

#ifdef __cplusplus
}
#endif

#endif /* SPFFA_LOCATION_STRATEGY_H */
