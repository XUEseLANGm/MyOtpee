// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include <limits>
#include <string.h>

#include "../smm_variable_mm_service.h"
#include "components/rpc/common/test/mock_rpc_interface.h"
#include "mock_assert.h"
#include "protocols/common/mm/mm_smc.h"
#include "protocols/service/smm_variable/smm_variable_proto.h"

TEST_GROUP(smm_variable_mm_service)
{
	TEST_SETUP()
	{
		mock_rpc_interface_init();

		memset(&service, 0x00, sizeof(service));
		memset(&rpc_iface, 0x00, sizeof(rpc_iface));
		memset(&rpc_req, 0x00, sizeof(rpc_req));
		memset(&mm_req, 0x00, sizeof(mm_req));
	}

	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().removeAllComparatorsAndCopiers();
		mock().clear();
	}

	struct smm_variable_mm_service service = { 0 };
	struct rpc_service_interface rpc_iface = { 0 };
	struct rpc_request rpc_req = { 0 };
	struct mm_service_call_req mm_req = { 0 };
};

TEST(smm_variable_mm_service, init_null_service)
{
	assert_environment_t env;

	if (SETUP_ASSERT_ENVIRONMENT(env)) {
		smm_variable_mm_service_init(NULL, NULL);
	}
}

TEST(smm_variable_mm_service, init_null_iface)
{
	assert_environment_t env;

	if (SETUP_ASSERT_ENVIRONMENT(env)) {
		smm_variable_mm_service_init(&service, NULL);
	}
}

TEST(smm_variable_mm_service, init)
{
	struct mm_service_interface *mm_service = NULL;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	POINTERS_EQUAL(mm_service, &service.mm_service);
	POINTERS_EQUAL(&rpc_iface, service.iface);
	POINTERS_EQUAL(mm_service, mm_service->context);
	CHECK(mm_service->receive != NULL);
}

TEST(smm_variable_mm_service, receive_too_small)
{
	struct mm_service_interface *mm_service = NULL;
	int32_t result = 0;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	mm_req.req_buf.data_length = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE - 1;
	result = mm_service->receive(mm_service, &mm_req);
	LONGS_EQUAL(MM_RETURN_CODE_DENIED, result);
}

TEST(smm_variable_mm_service, receive_zero_data)
{
	struct mm_service_interface *mm_service = NULL;
	uint8_t buffer[128] = { 0 };
	SMM_VARIABLE_COMMUNICATE_HEADER *header = (SMM_VARIABLE_COMMUNICATE_HEADER *)buffer;
	int32_t result = 0;

	mm_req.req_buf.size = sizeof(buffer);
	mm_req.req_buf.data_length = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	mm_req.req_buf.data = buffer;

	mm_req.resp_buf.size = sizeof(buffer);
	mm_req.resp_buf.data_length = 0;
	mm_req.resp_buf.data = buffer;

	header->Function = 0x0123456789abcdefULL;
	header->ReturnStatus = 0;

	rpc_req.opcode = header->Function;
	rpc_req.service_status = 0xfedcba9876543210ULL;
	rpc_req.request.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.request.data_length = 0;
	rpc_req.request.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.data_length = 16;
	rpc_req.response.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_iface.receive = mock_rpc_interface_receive;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	expect_mock_rpc_interface_receive(&rpc_iface, &rpc_req, RPC_SUCCESS);
	result = mm_service->receive(mm_service, &mm_req);

	LONGS_EQUAL(MM_RETURN_CODE_SUCCESS, result);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.service_status, header->ReturnStatus);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.response.data_length +
					 SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
				 mm_req.resp_buf.data_length);
}

TEST(smm_variable_mm_service, receive_data)
{
	struct mm_service_interface *mm_service = NULL;
	uint8_t buffer[128] = { 0 };
	SMM_VARIABLE_COMMUNICATE_HEADER *header = (SMM_VARIABLE_COMMUNICATE_HEADER *)buffer;
	int32_t result = 0;

	mm_req.req_buf.size = sizeof(buffer);
	mm_req.req_buf.data_length = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + 32;
	mm_req.req_buf.data = buffer;

	mm_req.resp_buf.size = sizeof(buffer);
	mm_req.resp_buf.data_length = 0;
	mm_req.resp_buf.data = buffer;

	header->Function = 0x0123456789abcdefULL;
	header->ReturnStatus = 0;

	rpc_req.opcode = header->Function;
	rpc_req.service_status = 0xfedcba9876543210ULL;
	rpc_req.request.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.request.data_length = 32;
	rpc_req.request.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.data_length = 16;
	rpc_req.response.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_iface.receive = mock_rpc_interface_receive;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	expect_mock_rpc_interface_receive(&rpc_iface, &rpc_req, RPC_SUCCESS);
	result = mm_service->receive(mm_service, &mm_req);

	LONGS_EQUAL(MM_RETURN_CODE_SUCCESS, result);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.service_status, header->ReturnStatus);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.response.data_length +
					 SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
				 mm_req.resp_buf.data_length);
}

TEST(smm_variable_mm_service, receive_long_response)
{
	struct mm_service_interface *mm_service = NULL;
	uint8_t buffer[128] = { 0 };
	SMM_VARIABLE_COMMUNICATE_HEADER *header = (SMM_VARIABLE_COMMUNICATE_HEADER *)buffer;
	int32_t result = 0;

	mm_req.req_buf.size = sizeof(buffer);
	mm_req.req_buf.data_length = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + 32;
	mm_req.req_buf.data = buffer;

	mm_req.resp_buf.size = sizeof(buffer);
	mm_req.resp_buf.data_length = 0;
	mm_req.resp_buf.data = buffer;

	header->Function = 0x0123456789abcdefULL;
	header->ReturnStatus = 0;

	rpc_req.opcode = header->Function;
	rpc_req.service_status = 0xfedcba9876543210ULL;
	rpc_req.request.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.request.data_length = 32;
	rpc_req.request.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.data_length =
		std::numeric_limits<size_t>::max() - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + 1;
	rpc_req.response.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_iface.receive = mock_rpc_interface_receive;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	expect_mock_rpc_interface_receive(&rpc_iface, &rpc_req, RPC_SUCCESS);
	result = mm_service->receive(mm_service, &mm_req);

	LONGS_EQUAL(MM_RETURN_CODE_NO_MEMORY, result);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.service_status, header->ReturnStatus);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.response.data_length +
					 SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
				 mm_req.resp_buf.data_length);
}

TEST(smm_variable_mm_service, receive_response_larger_than_size)
{
	struct mm_service_interface *mm_service = NULL;
	uint8_t buffer[128] = { 0 };
	SMM_VARIABLE_COMMUNICATE_HEADER *header = (SMM_VARIABLE_COMMUNICATE_HEADER *)buffer;
	int32_t result = 0;

	mm_req.req_buf.size = sizeof(buffer);
	mm_req.req_buf.data_length = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + 32;
	mm_req.req_buf.data = buffer;

	mm_req.resp_buf.size = 15 + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	mm_req.resp_buf.data_length = 0;
	mm_req.resp_buf.data = buffer;

	header->Function = 0x0123456789abcdefULL;
	header->ReturnStatus = 0;

	rpc_req.opcode = header->Function;
	rpc_req.service_status = 0xfedcba9876543210ULL;
	rpc_req.request.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.request.data_length = 32;
	rpc_req.request.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.size = 15;
	rpc_req.response.data_length = 16;
	rpc_req.response.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_iface.receive = mock_rpc_interface_receive;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	expect_mock_rpc_interface_receive(&rpc_iface, &rpc_req, RPC_SUCCESS);
	result = mm_service->receive(mm_service, &mm_req);

	LONGS_EQUAL(MM_RETURN_CODE_NO_MEMORY, result);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.service_status, header->ReturnStatus);
	UNSIGNED_LONGLONGS_EQUAL(rpc_req.response.data_length +
					 SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
				 mm_req.resp_buf.data_length);
}

TEST(smm_variable_mm_service, receive_data_error_codes)
{
	struct mm_service_interface *mm_service = NULL;
	uint8_t buffer[128] = { 0 };
	SMM_VARIABLE_COMMUNICATE_HEADER *header = (SMM_VARIABLE_COMMUNICATE_HEADER *)buffer;
	int32_t result = 0;

	const struct {
		rpc_status_t rpc_status;
		int32_t mm_result;
	} status_mapping[] = {
		{ RPC_SUCCESS, MM_RETURN_CODE_SUCCESS },
		{ RPC_ERROR_INTERNAL, MM_RETURN_CODE_INVALID_PARAMETER },
		{ RPC_ERROR_INVALID_VALUE, MM_RETURN_CODE_INVALID_PARAMETER },
		{ RPC_ERROR_NOT_FOUND, MM_RETURN_CODE_NOT_SUPPORTED },
		{ RPC_ERROR_INVALID_STATE, MM_RETURN_CODE_INVALID_PARAMETER },
		{ RPC_ERROR_TRANSPORT_LAYER, MM_RETURN_CODE_INVALID_PARAMETER },
		{ RPC_ERROR_INVALID_REQUEST_BODY, MM_RETURN_CODE_INVALID_PARAMETER },
		{ RPC_ERROR_INVALID_RESPONSE_BODY, MM_RETURN_CODE_INVALID_PARAMETER },
		{ 1, MM_RETURN_CODE_NOT_SUPPORTED }

	};

	mm_req.req_buf.size = sizeof(buffer);
	mm_req.req_buf.data_length = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + 32;
	mm_req.req_buf.data = buffer;

	mm_req.resp_buf.size = sizeof(buffer);
	mm_req.resp_buf.data_length = 0;
	mm_req.resp_buf.data = buffer;

	header->Function = 0x0123456789abcdefULL;
	header->ReturnStatus = 0;

	rpc_req.opcode = header->Function;
	rpc_req.service_status = 0xfedcba9876543210ULL;
	rpc_req.request.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.request.data_length = 32;
	rpc_req.request.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.size = sizeof(buffer) - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;
	rpc_req.response.data_length = 16;
	rpc_req.response.data = buffer + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE;

	rpc_iface.receive = mock_rpc_interface_receive;

	mm_service = smm_variable_mm_service_init(&service, &rpc_iface);

	for (size_t i = 0; i < ARRAY_SIZE(status_mapping); i++) {
		expect_mock_rpc_interface_receive(&rpc_iface, &rpc_req,
						  status_mapping[i].rpc_status);
		result = mm_service->receive(mm_service, &mm_req);

		LONGS_EQUAL(status_mapping[i].mm_result, result);
		UNSIGNED_LONGLONGS_EQUAL(rpc_req.service_status, header->ReturnStatus);
		UNSIGNED_LONGLONGS_EQUAL(rpc_req.response.data_length +
						 SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
					 mm_req.resp_buf.data_length);
	}
}
