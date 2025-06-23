// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include "mock_rpc_interface.h"
#include "rpc_request_comparator.h"

static rpc_request_comparator req_comparator(rpc_request_comparator::mode_ignore_opstatus);

void mock_rpc_interface_init(void)
{
	mock().installComparator("call_req", req_comparator);
}

void expect_mock_rpc_interface_receive(void *context,
				       const struct rpc_request *req, rpc_status_t result)
{
	mock().expectOneCall("rpc_interface_receive").
		onObject(context).
		withOutputParameterReturning("service_status", &req->service_status, sizeof(req->service_status)).
		withOutputParameterReturning("resp_buf_data_len", &req->response.data_length,
					     sizeof(req->response.data_length)).
		withParameterOfType("call_req", "req", req).
		andReturnValue(result);
}

rpc_status_t mock_rpc_interface_receive(void *context,
					struct rpc_request *req)
{
	return mock().actualCall("rpc_interface_receive").
		onObject(context).
		withOutputParameter("service_status", &req->service_status).
		withOutputParameter("resp_buf_data_len", &req->response.data_length).
		withParameterOfType("call_req", "req", req).
		returnIntValue();
}
