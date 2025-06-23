/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpmb_provider.h"
#include "components/service/rpmb/backend/rpmb_backend.h"
#include "protocols/service/rpmb/packed-c/rpmb_proto.h"
#include "util.h"
#include <string.h>

static rpc_status_t get_dev_info_handler(void *context, struct rpc_request *req)
{
	struct rpmb_provider *this_context = (struct rpmb_provider *)context;
	struct rpmb_request_get_dev_info *request_desc = NULL;
	struct rpmb_response_get_dev_info *response_desc = NULL;

	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	if (req->response.size < sizeof(*response_desc))
		return RPC_ERROR_INVALID_RESPONSE_BODY;

	request_desc = (struct rpmb_request_get_dev_info *)(req->request.data);
	response_desc = (struct rpmb_response_get_dev_info *)(req->response.data);

	req->service_status = rpmb_backend_get_dev_info(this_context->backend, request_desc->dev_id,
							&response_desc->dev_info);

	if (!req->service_status)
		req->response.data_length = sizeof(*response_desc);

	return RPC_SUCCESS;
}

static bool validate_size(size_t header_size, uint32_t frame_count, size_t available_length,
			  size_t *total_size)
{
	/*
	 * Checking if [data frame count] * [data frame size] + [header size] fits into the RPC
	 * buffer.
	 */

	if (MUL_OVERFLOW(frame_count, sizeof(struct rpmb_data_frame), total_size))
		return false;

	if (ADD_OVERFLOW(*total_size, header_size, total_size))
		return false;

	if (*total_size > available_length)
		return false;

	return true;
}

static rpc_status_t data_request_handler(void *context, struct rpc_request *req)
{
	struct rpmb_provider *this_context = (struct rpmb_provider *)context;
	struct rpmb_request_data_request *request_desc = NULL;
	struct rpmb_response_data_request *response_desc = NULL;
	size_t response_frame_count = 0;
	size_t total_size = 0;

	if (req->request.data_length < sizeof(*request_desc))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	request_desc = (struct rpmb_request_data_request *)(req->request.data);

	if (!validate_size(sizeof(*request_desc), request_desc->request_frame_count,
			   req->request.data_length, &total_size))
		return RPC_ERROR_INVALID_REQUEST_BODY;

	if (!validate_size(sizeof(*response_desc), request_desc->max_response_frame_count,
			   req->response.size, &total_size))
		return RPC_ERROR_INVALID_RESPONSE_BODY;

	response_desc = (struct rpmb_response_data_request *)(req->response.data);
	response_frame_count = request_desc->max_response_frame_count;

	req->service_status = rpmb_backend_data_request(
		this_context->backend,
		request_desc->dev_id,
		request_desc->request_frames,
		request_desc->request_frame_count,
		response_desc->response_frames,
		&response_frame_count);

	if (!req->service_status) {
		if (!validate_size(sizeof(*response_desc), response_frame_count,
				   req->response.size, &total_size))
			return RPC_ERROR_INVALID_RESPONSE_BODY;

		response_desc->response_frame_count = response_frame_count;
		req->response.data_length = total_size;
	}

	return RPC_SUCCESS;
}

static const struct service_handler handler_table[] = {
	{TS_RPMB_OPCODE_GET_DEV_INFO,	get_dev_info_handler},
	{TS_RPMB_OPCODE_DATA_REQUEST,	data_request_handler},
};

struct rpc_service_interface *rpmb_provider_init(struct rpmb_provider *context,
						 struct rpmb_backend *backend,
						 const struct rpc_uuid *service_uuid)
{
	struct rpc_service_interface *rpc_interface = NULL;

	if (!context || !backend || !service_uuid)
		return NULL;

	service_provider_init(&context->base_provider, context, service_uuid, handler_table,
			      ARRAY_SIZE(handler_table));

	rpc_interface = service_provider_get_rpc_interface(&context->base_provider);

	context->backend = backend;

	return rpc_interface;
}

void rpmb_provider_deinit(struct rpmb_provider *context)
{
	(void)context;
}
