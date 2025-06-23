/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPC_CALLER_H
#define RPC_CALLER_H

#include "rpc_status.h"
#include "rpc_uuid.h"
#include <stddef.h>
#include <stdint.h>

/*
 * The rpc_caller public interface may be exported as a public interface to
 * a shared library.
 */
#ifdef EXPORT_PUBLIC_INTERFACE_RPC_CALLER
#define RPC_CALLER_EXPORTED __attribute__((__visibility__("default")))
#else
#define RPC_CALLER_EXPORTED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Shared memory descriptor of an RPC caller
 *
 */
struct rpc_caller_shared_memory {
	uint64_t id;	/** Implementation defined ID of the shared memory */
	void *buffer;	/** Address of the shared memory (virtual) */
	size_t size;	/** Size of the shared memory */
};

struct rpc_caller_interface {
	void *context;

	rpc_status_t (*open_session)(void *context, const struct rpc_uuid *service_uuid,
				     uint16_t endpoint_id);
	rpc_status_t (*find_and_open_session)(void *context, const struct rpc_uuid *service_uuid);
	rpc_status_t (*close_session)(void *context);

	rpc_status_t (*create_shared_memory)(void *context, size_t size,
					     struct rpc_caller_shared_memory *shared_memory);
	rpc_status_t (*release_shared_memory)(void *context,
					      struct rpc_caller_shared_memory *shared_memory);

	rpc_status_t (*call)(void *context, uint16_t opcode,
			     struct rpc_caller_shared_memory *shared_memory, size_t request_length,
			     size_t *response_length, service_status_t *service_status);
};

RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_open_session(struct rpc_caller_interface *caller,
				     const struct rpc_uuid *service_uuid,
				     uint16_t endpoint_id);

RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_find_and_open_session(struct rpc_caller_interface *caller,
					      const struct rpc_uuid *service_uuid);

RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_close_session(struct rpc_caller_interface *caller);

RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_create_shared_memory(struct rpc_caller_interface *caller, size_t size,
					     struct rpc_caller_shared_memory *shared_memory);

RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_release_shared_memory(struct rpc_caller_interface *caller,
					      struct rpc_caller_shared_memory *shared_memory);

RPC_CALLER_EXPORTED
rpc_status_t rpc_caller_call(struct rpc_caller_interface *caller, uint16_t opcode,
			     struct rpc_caller_shared_memory *shared_memory, size_t request_length,
			     size_t *response_length, service_status_t *service_status);

#ifdef __cplusplus
}
#endif

#endif /* RPC_CALLER_H */
