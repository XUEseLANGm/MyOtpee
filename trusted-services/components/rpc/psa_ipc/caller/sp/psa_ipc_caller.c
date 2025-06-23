/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "psa_ipc_caller.h"
#include "rpc_caller.h"
#include "rpc_status.h"
#include <openamp_messenger_api.h>
#include <trace.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

struct psa_ipc_caller_context {
	struct openamp_messenger openamp;
};

rpc_status_t open_session(void *context, const struct rpc_uuid *service_uuid, uint16_t endpoint_id)
{
	return RPC_SUCCESS;
}

rpc_status_t find_and_open_session(void *context, const struct rpc_uuid *service_uuid)
{
	return RPC_SUCCESS;
}

rpc_status_t close_session(void *context)
{
	return RPC_SUCCESS;
}

rpc_status_t create_shared_memory(void *context, size_t size,
				  struct rpc_caller_shared_memory *shared_memory)
{
	return RPC_ERROR_INVALID_VALUE;
}

rpc_status_t release_shared_memory(void *context, struct rpc_caller_shared_memory *shared_memory)
{
	return RPC_ERROR_INVALID_VALUE;
}

rpc_status_t call(void *context, uint16_t opcode, struct rpc_caller_shared_memory *shared_memory,
		  size_t request_length, size_t *response_length, service_status_t *service_status)
{
	return RPC_ERROR_INTERNAL;
}

void *psa_ipc_phys_to_virt(void *context, void *pa)
{
	struct psa_ipc_caller_context *caller = (struct psa_ipc_caller_context *)context;
	struct openamp_messenger *openamp = &caller->openamp;

	return openamp_messenger_phys_to_virt(openamp, pa);
}

void *psa_ipc_virt_to_phys(void *context, void *va)
{
	struct psa_ipc_caller_context *caller = (struct psa_ipc_caller_context *)context;
	struct openamp_messenger *openamp = &caller->openamp;

	return openamp_messenger_virt_to_phys(openamp, va);
}

rpc_status_t psa_ipc_caller_init(struct rpc_caller_interface *rpc_caller)
{
	struct psa_ipc_caller_context *context = NULL;
	int ret = 0;

	if (!rpc_caller || rpc_caller->context)
		return RPC_ERROR_INVALID_VALUE;

	context = (struct psa_ipc_caller_context *)calloc(1, sizeof(struct psa_ipc_caller_context));
	if (!context)
		return RPC_ERROR_INTERNAL;

	ret = openamp_messenger_init(&context->openamp);
	if (ret < 0) {
		free(context);
		return RPC_ERROR_TRANSPORT_LAYER;
	}

	rpc_caller->context = context;
	rpc_caller->open_session = open_session;
	rpc_caller->find_and_open_session = find_and_open_session;
	rpc_caller->close_session = close_session;
	rpc_caller->create_shared_memory = create_shared_memory;
	rpc_caller->release_shared_memory = release_shared_memory;
	rpc_caller->call = call;

	return RPC_SUCCESS;
}

rpc_status_t psa_ipc_caller_deinit(struct rpc_caller_interface *rpc_caller)
{
	struct psa_ipc_caller_context *context = NULL;

	context = (struct psa_ipc_caller_context *)rpc_caller->context;

	openamp_messenger_deinit(&context->openamp);

	free(context);

	return RPC_SUCCESS;
}

psa_ipc_call_handle psa_ipc_caller_begin(struct rpc_caller_interface *caller,
					 uint8_t **request_buffer,
					 size_t request_length)
{
	struct psa_ipc_caller_context *context = NULL;
	int ret = 0;

	if (!caller || !caller->context)
		return NULL;

	context = (struct psa_ipc_caller_context *)caller->context;

	ret = openamp_messenger_call_begin(&context->openamp, request_buffer, request_length);
	if (ret < 0)
		return NULL;

	return caller;

}

rpc_status_t psa_ipc_caller_invoke(psa_ipc_call_handle handle, uint32_t opcode,
				   uint8_t **response_buffer, size_t *response_length)
{
	struct rpc_caller_interface *caller = (struct rpc_caller_interface *)handle;
	struct psa_ipc_caller_context *context = NULL;
	int ret = 0;

	if (!handle || !caller->context)
		return RPC_ERROR_INVALID_VALUE;

	context = (struct psa_ipc_caller_context *)caller->context;

	ret = openamp_messenger_call_invoke(&context->openamp, response_buffer, response_length);
	if (ret < 0)
		return RPC_ERROR_TRANSPORT_LAYER;

	return RPC_SUCCESS;
}

rpc_status_t psa_ipc_caller_end(psa_ipc_call_handle handle)
{
	struct rpc_caller_interface *caller = (struct rpc_caller_interface *)handle;
	struct psa_ipc_caller_context *context = NULL;

	if (!handle || !caller->context)
		return RPC_ERROR_INVALID_VALUE;

	context = (struct psa_ipc_caller_context *)caller->context;

	openamp_messenger_call_end(&context->openamp);

	return RPC_SUCCESS;
}