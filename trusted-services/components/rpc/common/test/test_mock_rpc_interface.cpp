// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include <string.h>
#include "mock_rpc_interface.h"

TEST_GROUP(mock_rpc_interface)
{
	TEST_SETUP()
	{
		mock_rpc_interface_init();
		memset(&iface, 0x00, sizeof(iface));
	}

	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().removeAllComparatorsAndCopiers();
		mock().clear();
	}

	struct rpc_service_interface iface;
};

TEST(mock_rpc_interface, receive)
{
	rpc_status_t res = RPC_ERROR_INTERNAL;
	struct rpc_request expected_req = { 0 };
	struct rpc_request req = { 0 };

	iface.context = (void *)1;
	iface.receive = mock_rpc_interface_receive;

	expected_req.source_id = 0x4567;
	expected_req.interface_id = 0xef;
	expected_req.opcode = 0xba98;
	expected_req.client_id = 0x76543210;
	expected_req.service_status = (service_status_t)-1;

	expected_req.request.size = 1;
	expected_req.request.data_length = 2;
	expected_req.request.data = (uint8_t *)3;

	expected_req.response.size = 4;
	expected_req.response.data_length = 5;
	expected_req.response.data = (uint8_t *)6;

	memcpy(&req, &expected_req, sizeof(req));
	req.service_status = 0;
	req.response.data_length = 0;

	expect_mock_rpc_interface_receive(&iface, &expected_req, res);
	LONGS_EQUAL(res, mock_rpc_interface_receive(&iface, &req));

	UNSIGNED_LONGLONGS_EQUAL(expected_req.service_status, req.service_status);
	UNSIGNED_LONGLONGS_EQUAL(expected_req.response.data_length, req.response.data_length);
}
