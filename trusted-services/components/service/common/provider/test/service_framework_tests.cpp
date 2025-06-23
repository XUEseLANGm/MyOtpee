/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string>
#include <cstring>
#include <service/common/provider/service_provider.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <rpc/direct/direct_caller.h>
#include "rpc/common/caller/rpc_caller_session.h"
#include <CppUTest/TestHarness.h>


TEST_GROUP(ServiceFrameworkTests)
{
	static rpc_status_t handlerThatSucceeds(void *context, struct rpc_request* req)
	{
		(void)context;

		struct rpc_buffer *respBuf = &req->response;

		std::string responseString("Yay!");
		respBuf->data_length = responseString.copy((char*)respBuf->data, respBuf->size);

		req->service_status = SERVICE_SPECIFIC_SUCCESS_CODE;

		return RPC_SUCCESS;
	}

	static rpc_status_t handlerThatFails(void *context, struct rpc_request* req)
	{
		(void)context;

		struct rpc_buffer *respBuf = &req->response;

		std::string responseString("Ehh!");
		respBuf->data_length = responseString.copy((char*)respBuf->data, respBuf->size);

		req->service_status = SERVICE_SPECIFIC_ERROR_CODE;

		return RPC_SUCCESS;
	}

	void setup()
	{
		memset(&m_direct_caller, 0, sizeof(m_direct_caller));
		memset(&m_session, 0, sizeof(m_session));
	}

	void teardown()
	{
		rpc_caller_session_close(&m_session);
		direct_caller_deinit(&m_direct_caller);
	}

	static const uint32_t SOME_ARBITRARY_OPCODE = 666;
	static const uint32_t ANOTHER_ARBITRARY_OPCODE = 901;
	static const uint32_t YET_ANOTHER_ARBITRARY_OPCODE = 7;
	static const int SERVICE_SPECIFIC_ERROR_CODE = 101;
	static const int SERVICE_SPECIFIC_SUCCESS_CODE = 100;

	struct rpc_caller_interface m_direct_caller;
	struct rpc_caller_session m_session;
};

TEST(ServiceFrameworkTests, serviceWithNoOps)
{
	/* Constructs a service endpoint with no handlers */
	struct rpc_uuid service_uuid = { .uuid = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
	struct service_provider service_provider;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	service_provider_init(&service_provider, &service_provider, &service_uuid, NULL, 0);
	rpc_status = direct_caller_init(&m_direct_caller,
					service_provider_get_rpc_interface(&service_provider));
	LONGS_EQUAL(RPC_SUCCESS, rpc_status);

	rpc_status = rpc_caller_session_find_and_open(&m_session, &m_direct_caller, &service_uuid,
						      4096);
	LONGS_EQUAL(RPC_SUCCESS, rpc_status);

	rpc_call_handle handle;
	uint8_t *req_buf;
	uint8_t *resp_buf;
	size_t req_len = 100;
	size_t resp_len;
	service_status_t service_status;

	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, SOME_ARBITRARY_OPCODE, &resp_buf, &resp_len,
					       &service_status);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_ERROR_INVALID_VALUE, rpc_status);
}

TEST(ServiceFrameworkTests, serviceWithOps)
{
	/* Constructs a service endpoint with a couple of handlers */
	struct rpc_uuid service_uuid = { .uuid = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
	struct service_handler handlers[2];
	handlers[0].opcode = SOME_ARBITRARY_OPCODE;
	handlers[0].invoke = handlerThatSucceeds;
	handlers[1].opcode = ANOTHER_ARBITRARY_OPCODE;
	handlers[1].invoke = handlerThatFails;

	struct service_provider service_provider;
	rpc_status_t rpc_status;

	service_provider_init(&service_provider, &service_provider, &service_uuid, handlers, 2);
	rpc_status = direct_caller_init(&m_direct_caller,
					service_provider_get_rpc_interface(&service_provider));
	LONGS_EQUAL(RPC_SUCCESS, rpc_status);

	rpc_status = rpc_caller_session_find_and_open(&m_session, &m_direct_caller, &service_uuid,
						      4096);
	LONGS_EQUAL(RPC_SUCCESS, rpc_status);

	rpc_call_handle handle;
	uint8_t *req_buf;
	uint8_t *resp_buf;
	size_t req_len = 100;
	size_t resp_len;
	service_status_t service_status;
	std::string respString;

	/* Expect this call transaction to succeed */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, SOME_ARBITRARY_OPCODE, &resp_buf, &resp_len,
					       &service_status);

	respString = std::string((const char*)resp_buf, resp_len);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_SUCCESS, rpc_status);
	LONGS_EQUAL(SERVICE_SPECIFIC_SUCCESS_CODE, service_status);
	STRCMP_EQUAL("Yay!", respString.c_str());

	/* Expect this call transaction to fail */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, ANOTHER_ARBITRARY_OPCODE, &resp_buf,
					       &resp_len, &service_status);

	respString = std::string((const char*)resp_buf, resp_len);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_SUCCESS, rpc_status);
	LONGS_EQUAL(SERVICE_SPECIFIC_ERROR_CODE, service_status);
	STRCMP_EQUAL("Ehh!", respString.c_str());

	/* Try an unsupported opcode */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, YET_ANOTHER_ARBITRARY_OPCODE, &resp_buf, &resp_len,
					       &service_status);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_ERROR_INVALID_VALUE, rpc_status);
}

TEST(ServiceFrameworkTests, serviceProviderChain)
{
	struct rpc_uuid service_uuid = { .uuid = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
	rpc_status_t rpc_status;

	/* Construct the base service provider */
	struct service_handler base_handlers[1];
	base_handlers[0].opcode = 100;
	base_handlers[0].invoke = handlerThatSucceeds;

	struct service_provider base_provider;
	service_provider_init(&base_provider, &base_provider, &service_uuid, base_handlers, 1);

	/* Construct a sub provider and extend the base */
	struct service_handler sub0_handlers[1];
	sub0_handlers[0].opcode = 200;
	sub0_handlers[0].invoke = handlerThatSucceeds;

	struct service_provider sub0_provider;
	service_provider_init(&sub0_provider, &sub0_provider, &service_uuid, sub0_handlers, 1);
	service_provider_extend(&base_provider, &sub0_provider);

	/* Construct another sub provider and extend the base */
	struct service_handler sub1_handlers[1];
	sub1_handlers[0].opcode = 300;
	sub1_handlers[0].invoke = handlerThatSucceeds;

	struct service_provider sub1_provider;
	service_provider_init(&sub1_provider, &sub1_provider, &service_uuid, sub1_handlers, 1);
	service_provider_extend(&base_provider, &sub1_provider);

	/* Use a direct_caller to make RPC calls to the base provider at the head of the chain */
	rpc_status = direct_caller_init(&m_direct_caller,
					service_provider_get_rpc_interface(&base_provider));
	LONGS_EQUAL(rpc_status, RPC_SUCCESS);

	rpc_status = rpc_caller_session_find_and_open(&m_session, &m_direct_caller, &service_uuid,
						      4096);
	LONGS_EQUAL(rpc_status, RPC_SUCCESS);

	rpc_call_handle handle;
	uint8_t *req_buf;
	uint8_t *resp_buf;
	size_t req_len = 100;
	size_t resp_len;
	service_status_t service_status;
	std::string respString;

	/* Expect calls that will be handled by all three chained service providers to succeed */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, 100, &resp_buf, &resp_len, &service_status);
	LONGS_EQUAL(RPC_SUCCESS, rpc_status);

	respString = std::string((const char*)resp_buf, resp_len);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_SUCCESS, rpc_status);
	LONGS_EQUAL(SERVICE_SPECIFIC_SUCCESS_CODE, service_status);
	STRCMP_EQUAL("Yay!", respString.c_str());

	/* This one should beb handled by sub0 */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, 200, &resp_buf, &resp_len, &service_status);

	respString = std::string((const char*)resp_buf, resp_len);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_SUCCESS, rpc_status);
	LONGS_EQUAL(SERVICE_SPECIFIC_SUCCESS_CODE, service_status);
	STRCMP_EQUAL("Yay!", respString.c_str());

	/* This one should beb handled by sub1 */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, 300, &resp_buf, &resp_len, &service_status);

	respString = std::string((const char*)resp_buf, resp_len);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_SUCCESS, rpc_status);
	LONGS_EQUAL(SERVICE_SPECIFIC_SUCCESS_CODE, service_status);
	STRCMP_EQUAL("Yay!", respString.c_str());

	/* Try an unsupported opcode */
	handle = rpc_caller_session_begin(&m_session, &req_buf, req_len, 0);
	CHECK_TRUE(handle);

	rpc_status = rpc_caller_session_invoke(handle, 400, &resp_buf, &resp_len, &service_status);

	rpc_caller_session_end(handle);

	LONGS_EQUAL(RPC_ERROR_INVALID_VALUE, rpc_status);
}
