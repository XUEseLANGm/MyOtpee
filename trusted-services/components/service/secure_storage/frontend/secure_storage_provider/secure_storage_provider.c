/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "secure_storage_provider.h"
#include "components/common/utils/include/util.h"
#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include "protocols/service/secure_storage/packed-c/secure_storage_proto.h"

static rpc_status_t set_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_request_set *request_desc = NULL;
	size_t request_length = 0;

	/* Checking if the descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct secure_storage_request_set *)(req->request.data);

	/* Checking for overflow */
	if (ADD_OVERFLOW(sizeof(*request_desc), request_desc->data_length, &request_length))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	/* Checking if the request descriptor and the data fits into the request buffer */
	if (req->request.data_length < request_length)
		return RPC_ERROR_INVALID_REQUEST_BODY;

	req->service_status = this_context->backend->interface->set(
		this_context->backend->context, req->source_id, request_desc->uid,
		request_desc->data_length, request_desc->p_data,
		request_desc->create_flags);

	return RPC_SUCCESS;
}

static rpc_status_t get_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_request_get *request_desc = NULL;

	/* Checking if the request descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct secure_storage_request_get *)(req->request.data);

	/* Clip the requested data size if it's too big for the response buffer */
	size_t data_size = MIN(req->response.size, request_desc->data_size);

	req->service_status = this_context->backend->interface->get(
		this_context->backend->context, req->source_id, request_desc->uid,
		request_desc->data_offset, data_size,
		req->response.data, &req->response.data_length);

	return RPC_SUCCESS;
}

static rpc_status_t get_info_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_request_get_info *request_desc = NULL;
	struct secure_storage_response_get_info *response_desc = NULL;
	struct psa_storage_info_t storage_info = { 0 };

	/* Checking if the descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct secure_storage_request_get_info *)(req->request.data);

	/* Checking if the response structure would fit the response buffer */
	if (req->response.size < sizeof(*response_desc))
		return RPC_ERROR_INVALID_RESPONSE_BODY;

	response_desc = (struct secure_storage_response_get_info *)(req->response.data);

	req->service_status = this_context->backend->interface->get_info(
		this_context->backend->context, req->source_id, request_desc->uid, &storage_info);

	if (req->service_status == PSA_SUCCESS) {
		response_desc->capacity = storage_info.capacity;
		response_desc->size = storage_info.size;
		response_desc->flags = storage_info.flags;
		req->response.data_length = sizeof(*response_desc);
	}

	return RPC_SUCCESS;
}

static rpc_status_t remove_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_request_remove *request_desc = NULL;

	/* Checking if the descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct secure_storage_request_remove *)(req->request.data);

	req->service_status = this_context->backend->interface->remove(
		this_context->backend->context, req->source_id, request_desc->uid);

	return RPC_SUCCESS;
}

static rpc_status_t create_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_request_create *request_desc = NULL;

	/* Checking if the descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct secure_storage_request_create *)(req->request.data);

	req->service_status = this_context->backend->interface->create(
		this_context->backend->context, req->source_id, request_desc->uid,
		request_desc->capacity, request_desc->create_flags);

	return RPC_SUCCESS;
}

static rpc_status_t set_extended_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_request_set_extended *request_desc = NULL;
	size_t request_length = 0;

	/* Checking if the descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct secure_storage_request_set_extended *)(req->request.data);

	/* Checking for overflow */
	if (ADD_OVERFLOW(sizeof(*request_desc), request_desc->data_length, &request_length))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	/* Checking if the request descriptor and the data fits into the request buffer */
	if (req->request.data_length < request_length)
		return RPC_ERROR_INVALID_REQUEST_BODY;

	req->service_status = this_context->backend->interface->set_extended(
		this_context->backend->context, req->source_id, request_desc->uid,
		request_desc->data_offset, request_desc->data_length, request_desc->p_data);

	return RPC_SUCCESS;
}

static rpc_status_t get_support_handler(void *context, struct rpc_request *req)
{
	struct secure_storage_provider *this_context = (struct secure_storage_provider*)context;
	struct secure_storage_response_get_support *response_desc = NULL;
	uint32_t feature_map;

	/* Checking if the response structure would fit the response buffer */
	if (req->response.size < sizeof(struct secure_storage_response_get_support))
		return RPC_ERROR_INVALID_RESPONSE_BODY;

	response_desc = (struct secure_storage_response_get_support *)(req->response.data);

	feature_map = this_context->backend->interface->get_support(this_context->backend->context,
				req->source_id);

	req->service_status = PSA_SUCCESS;
	response_desc->support = feature_map;
	req->response.data_length = sizeof(struct secure_storage_response_get_support);

	return RPC_SUCCESS;
}

/* Handler mapping table for service */
static const struct service_handler handler_table[] = {
	{TS_SECURE_STORAGE_OPCODE_SET,	set_handler},
	{TS_SECURE_STORAGE_OPCODE_GET,	get_handler},
	{TS_SECURE_STORAGE_OPCODE_GET_INFO,	get_info_handler},
	{TS_SECURE_STORAGE_OPCODE_REMOVE,	remove_handler},
	{TS_SECURE_STORAGE_OPCODE_CREATE,	create_handler},
	{TS_SECURE_STORAGE_OPCODE_SET_EXTENDED,	set_extended_handler},
	{TS_SECURE_STORAGE_OPCODE_GET_SUPPORT,	get_support_handler}
};

struct rpc_service_interface *secure_storage_provider_init(struct secure_storage_provider *context,
							   struct storage_backend *backend,
							   const struct rpc_uuid *service_uuid)
{
	struct rpc_service_interface *rpc_interface = NULL;

	if (!context || !backend)
		return NULL;

	service_provider_init(&context->base_provider, context, service_uuid, handler_table,
				  sizeof(handler_table) / sizeof(handler_table[0]));

	rpc_interface = service_provider_get_rpc_interface(&context->base_provider);

	context->backend = backend;

	return rpc_interface;
}

void secure_storage_provider_deinit(struct secure_storage_provider *context)
{
	(void)context;
}
