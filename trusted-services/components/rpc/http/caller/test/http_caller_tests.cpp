/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>

#include "protocols/rpc/common/packed-c/status.h"
#include "protocols/service/discovery/packed-c/opcodes.h"
#include "psa/error.h"
#include "rpc/http/caller/http_caller.h"
#include "service/locator/remote/restapi/restapi_location.h"

/*
 * http_caller tests rely on a fw test api server running on the local host
 */
TEST_GROUP(RpcCallerTests)
{
	void setup()
	{
		rpc_caller = http_caller_init(&http_caller_under_test);
		CHECK_TRUE(rpc_caller);
	}

	void teardown()
	{
		http_caller_deinit(&http_caller_under_test);
	}

	http_caller http_caller_under_test;
	struct rpc_caller *rpc_caller;
};

TEST(RpcCallerTests, probeAvailableHttpEndpoint)
{
	long http_code = 0;

	CHECK_TRUE(http_caller_probe(RESTAPI_LOCATOR_API_URL, &http_code));
	LONGS_EQUAL(200, http_code);
}

TEST(RpcCallerTests, probeUnavailableHost)
{
	long http_code = 0;

	CHECK_FALSE(http_caller_probe("http://127.0.0.1:5001/", &http_code));
	LONGS_EQUAL(0, http_code);
}

TEST(RpcCallerTests, callUnavailableApiEndpoint)
{
	int status;

	status = http_caller_open(&http_caller_under_test, RESTAPI_LOCATOR_API_URL "foo/call/");
	LONGS_EQUAL(0, status);

	rpc_call_handle call_handle;
	uint8_t *req_buf = NULL;

	call_handle = rpc_caller_begin(rpc_caller, &req_buf, 48);
	CHECK_TRUE(call_handle);
	CHECK_TRUE(req_buf);

	rpc_status_t rpc_status;
	rpc_opstatus_t op_status;
	uint8_t *resp_buf = NULL;
	size_t resp_len = 0;

	rpc_status =
		rpc_caller_invoke(rpc_caller, call_handle, 251, &op_status, &resp_buf, &resp_len);
	LONGS_EQUAL(TS_RPC_ERROR_EP_DOES_NOT_EXIT, rpc_status);

	rpc_caller_end(rpc_caller, call_handle);
}

TEST(RpcCallerTests, callAvailableApiEndpoint)
{
	int status;

	status = http_caller_open(&http_caller_under_test, RESTAPI_LOCATOR_API_URL "fwu/call/");
	LONGS_EQUAL(0, status);

	rpc_call_handle call_handle;
	uint8_t *req_buf = NULL;

	call_handle = rpc_caller_begin(rpc_caller, &req_buf, 48);
	CHECK_TRUE(call_handle);
	CHECK_TRUE(req_buf);

	rpc_status_t rpc_status;
	rpc_opstatus_t op_status;
	uint8_t *resp_buf = NULL;
	size_t resp_len = 0;

	rpc_status = rpc_caller_invoke(rpc_caller, call_handle,
				       TS_DISCOVERY_OPCODE_GET_SERVICE_INFO, &op_status, &resp_buf,
				       &resp_len);
	LONGS_EQUAL(TS_RPC_CALL_ACCEPTED, rpc_status);
	LONGS_EQUAL(PSA_SUCCESS, op_status);
	CHECK_TRUE(resp_len > 0);

	rpc_caller_end(rpc_caller, call_handle);
}
