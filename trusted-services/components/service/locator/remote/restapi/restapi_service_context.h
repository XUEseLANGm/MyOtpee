/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RESTAPI_SERVICE_CONTEXT_H
#define RESTAPI_SERVICE_CONTEXT_H

#include "service_locator.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Construct a service context
 *
 * Factory method to create a service context to represent a service instance
 * reachable using the provided URL.
 *
 * \param[in] service_url    URL string for the service API endpoint
 *
 * \return Pointer to constructed service_context
 */
struct service_context *restapi_service_context_create(const char *service_url);

#ifdef __cplusplus
}
#endif

#endif /* RESTAPI_SERVICE_CONTEXT_H */
