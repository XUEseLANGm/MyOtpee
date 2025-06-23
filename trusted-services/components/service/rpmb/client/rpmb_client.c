/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpmb_client.h"
#include "protocols/service/rpmb/packed-c/rpmb_proto.h"
#include "util.h"
#include <string.h>

static psa_status_t rpmb_client_get_dev_info(void *context, uint32_t dev_id,
					     struct rpmb_dev_info *dev_info)
{
	struct rpmb_client *this_context = (struct rpmb_client *)context;
	struct rpmb_request_get_dev_info *request_desc = NULL;
	struct rpmb_response_get_dev_info *response_desc = NULL;
	size_t response_length = 0;
	rpc_call_handle handle = 0;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	service_status_t service_status = 0;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;

	handle = rpc_caller_session_begin(this_context->session, (uint8_t **)&request_desc,
					  sizeof(*request_desc), sizeof(*response_desc));
	if (!handle)
		return PSA_ERROR_GENERIC_ERROR;

	request_desc->dev_id = dev_id;

	rpc_status = rpc_caller_session_invoke(handle, TS_RPMB_OPCODE_GET_DEV_INFO,
					       (uint8_t **)&response_desc, &response_length,
					       &service_status);
	if (rpc_status != RPC_SUCCESS || response_length != sizeof(*response_desc))
		goto session_end;

	psa_status = service_status;

	if (psa_status == PSA_SUCCESS)
		*dev_info = response_desc->dev_info;

session_end:
	rpc_status = rpc_caller_session_end(handle);
	if (psa_status == PSA_SUCCESS && rpc_status != RPC_SUCCESS)
		psa_status = PSA_ERROR_GENERIC_ERROR;

	return psa_status;
}

static bool calculate_size(size_t header_size, uint32_t frame_count, size_t *frames_size,
			   size_t *total_size)
{
	/* Calculating [data frame count] * [data frame size] + [header size] */

	if (MUL_OVERFLOW(frame_count, sizeof(struct rpmb_data_frame), frames_size))
		return false;

	if (ADD_OVERFLOW(*frames_size, header_size, total_size))
		return false;

	return true;
}

static psa_status_t rpmb_client_data_request(void *context, uint32_t dev_id,
					     const struct rpmb_data_frame *request_frames,
					     size_t request_frame_count,
					     struct rpmb_data_frame *response_frames,
					     size_t *response_frame_count)
{
	struct rpmb_client *this_context = (struct rpmb_client *)context;
	/* Request */
	struct rpmb_request_data_request  *request_desc = NULL;
	size_t request_frames_length = 0;
	size_t request_length = 0;
	/* Response */
	struct rpmb_response_data_request *response_desc = NULL;
	size_t response_frames_max_length = 0;
	size_t response_frames_length = 0;
	size_t response_max_length = 0;
	size_t response_length = 0;
	rpc_call_handle handle = 0;
	/* Status */
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	service_status_t service_status = 0;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;

	/* Calculating request lengths */
	if (!calculate_size(sizeof(*request_desc), request_frame_count,
			    &request_frames_length, &request_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	/* Calculating response lengths */
	if (!calculate_size(sizeof(*response_desc), *response_frame_count,
			    &response_frames_max_length, &response_max_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	handle = rpc_caller_session_begin(this_context->session, (uint8_t **)&request_desc,
					  request_length, response_max_length);
	if (!handle)
		goto out;

	request_desc->dev_id = dev_id;
	request_desc->request_frame_count = request_frame_count;
	request_desc->max_response_frame_count = *response_frame_count;
	memcpy(request_desc->request_frames, request_frames, request_frames_length);

	rpc_status = rpc_caller_session_invoke(handle, TS_RPMB_OPCODE_DATA_REQUEST,
					       (uint8_t **)&response_desc, &response_length,
					       &service_status);
	if (rpc_status != RPC_SUCCESS)
		goto session_end;

	/* Checking if the response length is too small or large */
	if (response_length < sizeof(*response_desc) || response_length > response_max_length)
		goto session_end;

	/* Checking if the response data frames have the expected length */
	if (!calculate_size(sizeof(*response_desc), response_desc->response_frame_count,
			    &response_frames_length, &response_max_length))
		goto session_end;

	if (response_length != response_max_length)
		goto session_end;

	psa_status = service_status;

	if (psa_status == PSA_SUCCESS) {
		memcpy(response_frames, response_desc->response_frames, response_frames_length);
		*response_frame_count = response_desc->response_frame_count;
	} else {
		*response_frame_count = 0;
	}

session_end:
	rpc_status = rpc_caller_session_end(handle);
	if (psa_status == PSA_SUCCESS && rpc_status != RPC_SUCCESS)
		psa_status = PSA_ERROR_GENERIC_ERROR;

out:
	return psa_status;
}

struct rpmb_backend *rpmb_client_init(struct rpmb_client *context,
				      struct rpc_caller_session *session)
{
	static const struct rpmb_backend_interface interface = {
		rpmb_client_get_dev_info,
		rpmb_client_data_request
	};

	if (!context || !session)
		return NULL;

	context->backend.context = context;
	context->backend.interface = &interface;
	context->session = session;

	return &context->backend;
}

void rpmb_client_deinit(struct rpmb_client *context)
{
	(void)context;
}
