/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpc_service_interface.h"

rpc_status_t rpc_service_receive(struct rpc_service_interface *service,
				 struct rpc_request *request)
{
	if (!service)
		return RPC_ERROR_INVALID_VALUE;

	return service->receive(service->context, request);
}
