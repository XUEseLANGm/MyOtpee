/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RESTAPI_LOCATION_STRATEGY_H
#define RESTAPI_LOCATION_STRATEGY_H

#include "service_locator.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a service_location_strategy for locating a service reached via a
 * REST API that presents a call endpoint for RPC access to the service. The
 * FW Test API provides such call endpoints.
 */
const struct service_location_strategy *restapi_location_strategy(void);

#ifdef __cplusplus
}
#endif

#endif /* RESTAPI_LOCATION_STRATEGY_H */
