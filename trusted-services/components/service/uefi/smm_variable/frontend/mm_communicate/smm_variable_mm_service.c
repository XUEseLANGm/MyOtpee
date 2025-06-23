// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 */

#include "smm_variable_mm_service.h"

#include <assert.h>

#include "protocols/common/mm/mm_smc.h"
#include "protocols/service/smm_variable/smm_variable_proto.h"

struct smm_variable_rpc_context {
	struct rpc_interface *smm_variable_rpc_interface;
};

static service_status_t convert_rpc_status(rpc_status_t rpc_status)
{
	switch (rpc_status) {
	case RPC_SUCCESS:
		return MM_RETURN_CODE_SUCCESS;

	case RPC_ERROR_INTERNAL:
		return MM_RETURN_CODE_INVALID_PARAMETER;

	case RPC_ERROR_INVALID_VALUE:
		return MM_RETURN_CODE_INVALID_PARAMETER;

	case RPC_ERROR_NOT_FOUND:
		return MM_RETURN_CODE_NOT_SUPPORTED;

	case RPC_ERROR_INVALID_STATE:
		return MM_RETURN_CODE_INVALID_PARAMETER;

	case RPC_ERROR_TRANSPORT_LAYER:
		return MM_RETURN_CODE_INVALID_PARAMETER;

	case RPC_ERROR_INVALID_REQUEST_BODY:
		return MM_RETURN_CODE_INVALID_PARAMETER;

	case RPC_ERROR_INVALID_RESPONSE_BODY:
		return MM_RETURN_CODE_INVALID_PARAMETER;

	default:
		return MM_RETURN_CODE_NOT_SUPPORTED;
	}
}

static int32_t smm_var_receive(struct mm_service_interface *iface,
			       struct mm_service_call_req *mm_req)
{
	SMM_VARIABLE_COMMUNICATE_HEADER *header = NULL;
	struct smm_variable_mm_service *service = iface->context;
	struct rpc_request rpc_req = { 0 };
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	if (mm_req->req_buf.data_length < SMM_VARIABLE_COMMUNICATE_HEADER_SIZE)
		return MM_RETURN_CODE_DENIED;

	header = (SMM_VARIABLE_COMMUNICATE_HEADER *)mm_req->req_buf.data;

	rpc_req.opcode = header->Function;
	rpc_req.request.data = header->Data;
	rpc_req.request.data_length =
		mm_req->req_buf.data_length - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.request.size = mm_req->req_buf.size - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_req.response.data = header->Data;
	rpc_req.response.data_length = 0;
	rpc_req.response.size = mm_req->resp_buf.size - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_status = service->iface->receive(service->iface, &rpc_req);

	header->ReturnStatus = rpc_req.service_status;

	if (ADD_OVERFLOW(rpc_req.response.data_length, SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
			 &mm_req->resp_buf.data_length))
		return MM_RETURN_CODE_NO_MEMORY;

	if (mm_req->resp_buf.data_length > mm_req->resp_buf.size)
		return MM_RETURN_CODE_NO_MEMORY;

	return convert_rpc_status(rpc_status);
}

struct mm_service_interface *smm_variable_mm_service_init(struct smm_variable_mm_service *service,
							  struct rpc_service_interface *iface)
{
	assert(service != NULL);
	assert(iface != NULL);

	service->iface = iface;
	service->mm_service.context = service;
	service->mm_service.receive = smm_var_receive;

	return &service->mm_service;
}
