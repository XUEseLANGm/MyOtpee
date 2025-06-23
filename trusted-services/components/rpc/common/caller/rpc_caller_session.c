/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpc_caller_session.h"
#include "util.h"
#include <string.h>

static rpc_status_t initalize_shared_memory(struct rpc_caller_session *session,
					    struct rpc_caller_interface *caller,
					    size_t shared_memory_size)
{
	if (shared_memory_size) {
		rpc_status_t status = RPC_ERROR_INTERNAL;

		status = rpc_caller_create_shared_memory(caller, shared_memory_size,
							 &session->shared_memory);
		if (status) {
			rpc_caller_close_session(caller);
			return status;
		}

		session->shared_memory_policy = alloc_for_session;
	} else {
		session->shared_memory = (struct rpc_caller_shared_memory){ 0 };
		session->shared_memory_policy = alloc_for_each_call;
	}

	return RPC_SUCCESS;
}

rpc_status_t rpc_caller_session_open(struct rpc_caller_session *session,
				     struct rpc_caller_interface *caller,
				     const struct rpc_uuid *service_uuid,
				     uint16_t endpoint_id,
				     size_t shared_memory_size)
{
	rpc_status_t status = RPC_ERROR_INTERNAL;

	if (!session || !caller || !service_uuid)
		return RPC_ERROR_INVALID_VALUE;

	status = rpc_caller_open_session(caller, service_uuid, endpoint_id);
	if (status)
		return status;

	status = initalize_shared_memory(session, caller, shared_memory_size);
	if (status)
		return status;

	session->caller = caller;
	session->is_call_transaction_in_progress = false;
	session->request_length = 0;

	return status;
}

rpc_status_t rpc_caller_session_find_and_open(struct rpc_caller_session *session,
					      struct rpc_caller_interface *caller,
					      const struct rpc_uuid *service_uuid,
					      size_t shared_memory_size)
{
	rpc_status_t status = RPC_ERROR_INTERNAL;

	if (!session || !caller || !service_uuid)
		return RPC_ERROR_INVALID_VALUE;

	status = rpc_caller_find_and_open_session(caller, service_uuid);
	if (status)
		return status;

	status = initalize_shared_memory(session, caller, shared_memory_size);
	if (status)
		return status;

	session->caller = caller;
	session->is_call_transaction_in_progress = false;
	session->request_length = 0;

	return status;
}

rpc_status_t rpc_caller_session_close(struct rpc_caller_session *session)
{
	if (!session)
		return RPC_ERROR_INVALID_VALUE;

	if (session->is_call_transaction_in_progress)
		return RPC_ERROR_INVALID_STATE;

	if (session->shared_memory_policy == alloc_for_session) {
		rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

		rpc_status = rpc_caller_release_shared_memory(session->caller,
							      &session->shared_memory);
		if (rpc_status != RPC_SUCCESS)
			return rpc_status;
	}

	return rpc_caller_close_session(session->caller);
}

rpc_call_handle rpc_caller_session_begin(struct rpc_caller_session *session,
					 uint8_t **request_buffer, size_t request_length,
					 size_t response_max_length)
{
	rpc_status_t status = RPC_ERROR_INTERNAL;
	size_t required_buffer_length = MAX(request_length, response_max_length);

	if (required_buffer_length > UINT32_MAX)
		return NULL;

	if (!session || !request_buffer || session->is_call_transaction_in_progress)
		return NULL;

	switch (session->shared_memory_policy) {
	case alloc_for_each_call:
		if (session->shared_memory.buffer || session->shared_memory.size)
			return NULL; /* There's already a shared memory */

		status = rpc_caller_create_shared_memory(session->caller, required_buffer_length,
							 &session->shared_memory);
		if (status)
			return NULL; /* Failed to create shared memory */
		break;

	case alloc_for_session:
		if (!session->shared_memory.buffer || !session->shared_memory.size)
			return NULL; /* There's no shared memory */

		if (session->shared_memory.size < required_buffer_length)
			return NULL; /* The allocated shared memory is too small */
		break;

	default:
		/* Invalid shared memory policy */
		return NULL;
	}

	*request_buffer = session->shared_memory.buffer;

	session->is_call_transaction_in_progress = true;
	session->request_length = request_length;

	return (rpc_call_handle)session;
}

rpc_status_t rpc_caller_session_invoke(rpc_call_handle handle, uint32_t opcode,
				       uint8_t **response_buffer, size_t *response_length,
				       service_status_t *service_status)
{
	struct rpc_caller_session *session = (struct rpc_caller_session *)handle;
	rpc_status_t status = RPC_ERROR_INTERNAL;

	if (!handle || !response_buffer || !response_length)
		return RPC_ERROR_INVALID_VALUE;

	if (!session->is_call_transaction_in_progress)
		return RPC_ERROR_INVALID_STATE;

	if (session->request_length &&
	    (!session->shared_memory.buffer || !session->shared_memory.size))
		return RPC_ERROR_INVALID_STATE;

	status = rpc_caller_call(session->caller, opcode, &session->shared_memory,
				session->request_length, response_length, service_status);
	if (status || *response_length > session->shared_memory.size) {
		*response_buffer = NULL;
		*response_length = 0;
		return status;
	}

	*response_buffer = session->shared_memory.buffer;

	return status;
}

rpc_status_t rpc_caller_session_end(rpc_call_handle handle)
{
	struct rpc_caller_session *session = (struct rpc_caller_session *)handle;
	rpc_status_t status = RPC_ERROR_INTERNAL;

	if (!handle)
		return RPC_ERROR_INVALID_VALUE;

	if (!session->is_call_transaction_in_progress)
		return RPC_ERROR_INVALID_STATE;

	if (session->request_length &&
	    (!session->shared_memory.buffer || !session->shared_memory.size))
		return RPC_ERROR_INVALID_STATE; /* There's no shared memory */

	switch (session->shared_memory_policy) {
	case alloc_for_each_call:
		status = rpc_caller_release_shared_memory(session->caller,
								&session->shared_memory);
		if (status)
			return status; /* Failed to release shared memory */

		session->shared_memory = (struct rpc_caller_shared_memory){ 0 };
		break;

	case alloc_for_session:
		/* Nothing to do */
		break;

	default:
		return RPC_ERROR_INVALID_STATE;
	}

	session->is_call_transaction_in_progress = false;
	session->request_length = 0;

	return RPC_SUCCESS;
}
