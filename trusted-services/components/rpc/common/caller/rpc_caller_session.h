/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPC_CALLER_SESSION_H
#define RPC_CALLER_SESSION_H

#include "rpc_caller.h"
#include "rpc_status.h"
#include "rpc_uuid.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *rpc_call_handle;

enum rpc_caller_memory_policy {
	alloc_for_each_call = 0,
	alloc_for_session,
};

/**
 * @brief RPC caller session
 *
 * Builds a session on top of the rpc_caller_interface. It provides high level functions for service
 * caller implementations and for prior service discovery.
 */
struct rpc_caller_session {
	/** Caller interface */
	struct rpc_caller_interface *caller;

	/** Shared memory instance for the exchanging of RPC request and response parameters. */
	struct rpc_caller_shared_memory shared_memory;

	/** Controls how and when the shared memory is allocated for the RPC calls. */
	enum rpc_caller_memory_policy shared_memory_policy;

	/**
	 * Indicates if a call transaction has been started by the begin function but was not
	 * finished yet (i.e. end was not called).
	 */
	bool is_call_transaction_in_progress;

	/**
	 * Stores the request length of the current transaction. Its value is set by the begin
	 * function and then used in the invoke step.
	 */
	size_t request_length;
};

/**
 * @brief
 *
 * @param session
 * @param caller
 * @param service_uuid
 * @param endpoint_id
 * @param shared_memory_size
 * @return RPC_CALLER_EXPORTED
 */
RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_session_open(struct rpc_caller_session *session,
				     struct rpc_caller_interface *caller,
				     const struct rpc_uuid *service_uuid,
				     uint16_t endpoint_id,
				     size_t shared_memory_size);

/**
 * @brief
 *
 * @param session
 * @param caller
 * @param service_uuid
 * @param shared_memory_size
 * @return RPC_CALLER_EXPORTED
 */
RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_session_find_and_open(struct rpc_caller_session *session,
					      struct rpc_caller_interface *caller,
					      const struct rpc_uuid *service_uuid,
					      size_t shared_memory_size);

/**
 * @brief Closes the RPC caller session
 *
 * @param session Caller session instance
 * @return RPC_CALLER_EXPORTED
 */
RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_session_close(struct rpc_caller_session *session);

/**
 * @brief Begins an RPC call
 *
 * The function returns a buffer where the service caller can build the request.
 *
 * @param session Caller session instance
 * @param request_buffer Pointer of the request buffer
 * @param request_length Request length
 * @param response_max_length Expected maximal length of the response
 * @return rpc_call_handle Handle of the started call
 */
RPC_CALLER_EXPORTED
rpc_call_handle rpc_caller_session_begin(struct rpc_caller_session *session,
					 uint8_t **request_buffer,
					 size_t request_length,
					 size_t response_max_length);

/**
 * @brief Invoke phase of the RPC call
 *
 * Invokes the call on the remote side and returns the response buffer and service status. The
 * service caller can parse the response from the response buffer.
 * After this call the request buffer is not available for the service caller.
 *
 * @param handle RPC call handle
 * @param opcode The opcode of the remote function
 * @param response_buffer Pointer of the response buffer
 * @param response_length Length of the response buffer
 * @param service_status Service specific status code
 * @return RPC_CALLER_EXPORTED
 */
RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_session_invoke(rpc_call_handle handle, uint32_t opcode,
				       uint8_t **response_buffer,
				       size_t *response_length,
				       service_status_t *service_status);

/**
 * @brief Ends the RPC call
 *
 * Indicates if the response has been parsed by the service calls and the RPC session can free the
 * response buffer.
 *
 * @param handle RPC call handle
 * @return RPC_CALLER_EXPORTED
 */
RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_session_end(rpc_call_handle handle);


#ifdef __cplusplus
}
#endif

#endif /* RPC_CALLER_SESSION_H */
