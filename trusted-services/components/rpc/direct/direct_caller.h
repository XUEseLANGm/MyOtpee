/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DIRECT_CALLER_H
#define DIRECT_CALLER_H

#include "rpc_caller.h"

struct rpc_service_interface;

#ifdef __cplusplus
extern "C" {
#endif

/** An rpc_caller that calls methods associated with a specific endpoint
 *  directly.  Used when the caller and endpoint are running in the same
 *  execution context.
 **/

rpc_status_t direct_caller_init(struct rpc_caller_interface *caller,
				struct rpc_service_interface *service);

rpc_status_t direct_caller_deinit(struct rpc_caller_interface *caller);

#ifdef __cplusplus
}
#endif

#endif /* DIRECT_CALLER_H */
