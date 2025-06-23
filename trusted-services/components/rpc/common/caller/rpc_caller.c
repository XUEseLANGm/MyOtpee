/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpc_caller.h"

rpc_status_t rpc_caller_open_session(struct rpc_caller_interface *caller,
				     const struct rpc_uuid *service_uuid,
				     uint16_t endpoint_id)
{
	if (!caller)
		return RPC_ERROR_INVALID_VALUE;

	return caller->open_session(caller->context, service_uuid, endpoint_id);
}

rpc_status_t rpc_caller_find_and_open_session(struct rpc_caller_interface *caller,
					      const struct rpc_uuid *service_uuid)
{
	if (!caller)
		return RPC_ERROR_INVALID_VALUE;

	return caller->find_and_open_session(caller->context, service_uuid);
}

rpc_status_t rpc_caller_close_session(struct rpc_caller_interface *caller)
{
	if (!caller)
		return RPC_ERROR_INVALID_VALUE;

	return caller->close_session(caller->context);
}

rpc_status_t rpc_caller_create_shared_memory(struct rpc_caller_interface *caller, size_t length,
					     struct rpc_caller_shared_memory *shared_memory)
{
	if (!caller)
		return RPC_ERROR_INVALID_VALUE;

	return caller->create_shared_memory(caller->context, length, shared_memory);
}

rpc_status_t rpc_caller_release_shared_memory(struct rpc_caller_interface *caller,
					      struct rpc_caller_shared_memory *shared_memory)
{
	if (!caller)
		return RPC_ERROR_INVALID_VALUE;

	return caller->release_shared_memory(caller->context, shared_memory);
}

rpc_status_t rpc_caller_call(struct rpc_caller_interface *caller, uint16_t opcode,
			     struct rpc_caller_shared_memory *shared_memory, size_t request_length,
			     size_t *response_length, service_status_t *service_status)
{
	if (!caller)
		return RPC_ERROR_INVALID_VALUE;

	return caller->call(caller->context, opcode, shared_memory, request_length,
			    response_length, service_status);
}
