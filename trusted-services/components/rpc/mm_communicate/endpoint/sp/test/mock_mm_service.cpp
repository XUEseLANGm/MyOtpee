// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include "mock_mm_service.h"
#include "mm_service_call_req_comparator.h"

static mm_service_call_req_comparator req_comparator;

void mock_mm_service_init(void)
{
	mock().installComparator("mm_service_call_req", req_comparator);
}

void expect_mock_mm_service_receive(struct mm_service_interface *iface,
				    const struct mm_service_call_req *req,
				    int64_t result)
{
	mock().expectOneCall("mm_service_receive").onObject(iface).
		withOutputParameterReturning("resp_buf_data_len", &req->resp_buf.data_length,
					     sizeof(req->resp_buf.data_length)).
		withParameterOfType("mm_service_call_req", "req", req).
		andReturnValue(result);
}

int32_t mock_mm_service_receive(struct mm_service_interface *iface,
				struct mm_service_call_req *req)
{
	return mock().actualCall("mm_service_receive").onObject(iface).
		withOutputParameter("resp_buf_data_len", &req->resp_buf.data_length).
		withParameterOfType("mm_service_call_req", "req", req).
		returnLongIntValue();
}
