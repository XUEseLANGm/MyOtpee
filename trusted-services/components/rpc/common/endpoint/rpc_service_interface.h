/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPC_INTERFACE_H
#define RPC_INTERFACE_H

#include "rpc_status.h"
#include "rpc_uuid.h"
#include <stddef.h>
#include <stdint.h>

#ifdef EXPORT_PUBLIC_INTERFACE_RPC_SERVICE
#define RPC_SERVICE_EXPORTED __attribute__((__visibility__("default")))
#else
#define RPC_SERVICE_EXPORTED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief RPC buffer
 *
 * Describes an RPC buffer by its data pointer, size and the used data length.
 */
struct rpc_buffer {
	uint8_t *data;
	size_t data_length;
	size_t size;
};

/**
 * @brief RPC request
 *
 * The service should select the requested function by the opcode field. The call's request and
 * response parameter buffer is accessible via the request and response rpc_buffers. The response's
 * size must be indicated by the service through setting the data_length field of the response.
 * The services can identify the caller via the source_id and client_id fields.
 */
struct rpc_request {
	uint16_t source_id;			/** Call source ID (i.e. FF-A source ID) */
	uint8_t interface_id;			/** Service interface ID */
	uint16_t opcode;			/** Opcode of the required function */
	uint32_t client_id;			/** Client ID for further caller identification */
	service_status_t service_status;	/** Service specific status code */
	struct rpc_buffer request;		/** Request buffer */
	struct rpc_buffer response;		/** Response buffer */
};

/**
 * @brief RPC service interface
 *
 * An endpoint (i.e. secure partition) can implement multiple services which are identified by their
 * service UUID. Once an endpoint receives an RPC call, it selects the matching
 * rpc_service_interface instance, builds the rpc_request structure and calls the interface's
 * receive function.
 * If the service is not able to parse the request (invalid opcode, request or response buffer)
 * it should return an rpc_status_t value indicating the issue with the RPC request. Otherwise it
 * must return RPC_SUCCESS.
 * Service level status codes should be passed in a service specific way.
 */
struct rpc_service_interface {
	void *context;
	struct rpc_uuid uuid;

	rpc_status_t (*receive)(void *context, struct rpc_request *request);
};

/**
 * @brief Call the receive function of the RPC interface.
 *
 * @param service The service instance
 * @param request RPC request
 * @return rpc_status_t
 */
RPC_SERVICE_EXPORTED
rpc_status_t rpc_service_receive(struct rpc_service_interface *service,
				 struct rpc_request *request);

#ifdef __cplusplus
}
#endif

#endif /* RPC_INTERFACE_H */
