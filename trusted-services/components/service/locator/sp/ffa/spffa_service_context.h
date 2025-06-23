/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SPFFA_SERVICE_CONTEXT_H
#define SPFFA_SERVICE_CONTEXT_H

#include <service_locator.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RPC_CALLER_SESSION_SHARED_MEMORY_SIZE
#define RPC_CALLER_SESSION_SHARED_MEMORY_SIZE	(4096)
#endif /* RPC_CALLER_SESSION_SHARED_MEMORY_SIZE */

/*
 * A service_context that represents a service instance located in
 * a partition, accessed via FFA.  This service_context is suitable
 * for use by client applications running in a secure partition.
 */
struct sp_ts_service_context
{
	struct service_context service_context;
	struct rpc_caller_interface caller;
	struct rpc_uuid service_uuid;
};

/*
 * Factory method to create a service context associated with the specified
 * partition id and RPC interface instance.
 */
struct sp_ts_service_context *spffa_service_context_create(const struct rpc_uuid *service_uuid);

#ifdef __cplusplus
}
#endif

#endif /* SPFFA_SERVICE_CONTEXT_H */
