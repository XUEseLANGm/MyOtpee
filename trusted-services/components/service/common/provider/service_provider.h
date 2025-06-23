/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SERVICE_PROVIDER_H
#define SERVICE_PROVIDER_H

#include "rpc/common/endpoint/rpc_service_interface.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Service handler
 *
 * Defines a mapping between an opcode and a handler function. A complete
 * service interface is defined by an array of service request handlers.
 */
struct service_handler {
	uint32_t opcode;
	rpc_status_t (*invoke)(void *context, struct rpc_request *req);
};

static inline int service_handler_invoke(const struct service_handler *handler, void *context,
					 struct rpc_request *req)
{
	return handler->invoke(context, req);
}

static inline uint32_t service_handler_get_opcode(const struct service_handler *handler)
{
	return handler->opcode;
}

/** \brief Service provider
 *
 * A generalised service provider that acts as an rpc call endpoint.  It receives call
 * requests and delegates them to the appropriate handle provided by a concrete service
 * provider.  To support service specialization and proxying, unhandled requests may
 * optionally be passed to a delegate rpc_interface to form a chain of responsibility.
 */
struct service_provider {
	struct rpc_service_interface iface;
	const struct service_handler *handlers;
	size_t num_handlers;
	uint32_t opcode_range_lo;
	uint32_t opcode_range_hi;
	struct rpc_service_interface *successor;
};

static inline struct rpc_service_interface *service_provider_get_rpc_interface(struct service_provider *sp)
{
	return &sp->iface;
}

void service_provider_init(struct service_provider *sp, void *context,
			   const struct rpc_uuid *service_uuid,
			   const struct service_handler *handlers, size_t num_handlers);

/*
 * Extend the core set of operations provided by a service provider by
 * adding a sub provider that will add a capability.  This facility
 * allows a deployment to customize the set of operations
 * supported to meet requirements by only extending the core service
 * provider if needed.
 */
void service_provider_extend(struct service_provider *context,
			     struct service_provider *sub_provider);

/*
 * Link a successor to this service provider to extend the chain of responsibility
 * to allow call handling to be delegated to different components.  Used to support
 * modular configuration of service capabilities.
 */
static inline void service_provider_link_successor(struct service_provider *sp,
						   struct rpc_service_interface *successor)
{
	sp->successor = successor;
}

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_PROVIDER_H */
