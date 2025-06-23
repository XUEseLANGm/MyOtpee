/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_RPC_ENDPOINT_SP_H
#define TS_RPC_ENDPOINT_SP_H

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include "components/rpc/ts_rpc/common/ts_rpc_abi.h"
#include "sp_messaging.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TS RPC shared memory
 *
 * The structure describes an FF-A shared memory slot in the endpoint implementation. The shared
 * memory is identified by its owner (FF-A ID) and handle (FF-A memory handle). After retrieval the
 * data and size fields are filled. The used field indicates if a given memory slot of the pool is
 * used and contains valid information.
 */
struct ts_rpc_shared_memory {
	uint16_t owner_id;
	uint64_t handle;
	void *data;
	size_t size;
	bool used;
};

/**
 * @brief TS RPC endpoint for SPs
 *
 * This component connects the FF-A layer and the services by implementing TS RPC on FF-A direct
 * messages and shared memories.
 * The structure contains the endpoint's own FF-A ID to be used in FF-A calls.
 * It also contains of list of services. These services are selected based on the interface ID of
 * the RPC request. The endpoint handles the shared memory pool.
 */
struct ts_rpc_endpoint_sp {
	uint16_t own_id;
	struct rpc_service_interface **services;
	size_t service_count;
	struct ts_rpc_shared_memory *shared_memories;
	size_t shared_memory_count;
};

/**
 * @brief Init TS RPC endpoint
 *
 * @param endpoint The endpoint instance
 * @param service_count Service count
 * @param shared_memory_count Shared memory pool size
 * @return rpc_status_t
 */
rpc_status_t ts_rpc_endpoint_sp_init(struct ts_rpc_endpoint_sp *endpoint, size_t service_count,
				     size_t shared_memory_count);

/**
 * @brief Deinit TS RPC endpoint
 *
 * @param endpoint The endpoint instance
 * @return rpc_status_t
 */
rpc_status_t ts_rpc_endpoint_sp_deinit(struct ts_rpc_endpoint_sp *endpoint);

/**
 * @brief Add service to the endpoint. The interface IDs are assigned sequentially. The maximal
 * service count is determined by the service_count parameter of ts_rpc_endpoint_sp_init.
 *
 * @param endpoint The endpoint instance
 * @param service The service instance
 * @return rpc_status_t
 */
rpc_status_t ts_rpc_endpoint_sp_add_service(struct ts_rpc_endpoint_sp *endpoint,
					    struct rpc_service_interface *service);

/**
 * @brief Handle received FF-A message
 *
 * @param endpoint The endpoint instance
 * @param request The request FF-A message
 * @param response The response FF-A message
 */
void ts_rpc_endpoint_sp_receive(struct ts_rpc_endpoint_sp *endpoint, const struct sp_msg *request,
				struct sp_msg *response);

#ifdef __cplusplus
}
#endif

#endif /* TS_RPC_ENDPOINT_SP_H */
