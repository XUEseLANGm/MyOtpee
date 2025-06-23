/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LINUXFFA_SERVICE_CONTEXT_H
#define LINUXFFA_SERVICE_CONTEXT_H

#include "service_locator.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A service_context that represents a service instance located in
 * a partition, accessed via FFA.  This service_context is suitable
 * for use by client applications running in Linux userspace.
 */
struct linux_ts_service_context;

/*
 * Factory method to create a service context associated with the specified
 * service UUID.
 */
struct linux_ts_service_context *linux_ts_service_context_create(const struct rpc_uuid *service_uuid);

#ifdef __cplusplus
}
#endif

#endif /* LINUXFFA_SERVICE_CONTEXT_H */
