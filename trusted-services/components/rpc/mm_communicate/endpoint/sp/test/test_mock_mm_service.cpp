// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include "mock_mm_service.h"

TEST_GROUP(mock_mm_service)
{
	TEST_SETUP()
	{
		mock_mm_service_init();
	}

	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().removeAllComparatorsAndCopiers();
		mock().clear();
	}
};

TEST(mock_mm_service, receive)
{
	struct mm_service_interface iface = {
		.context = (void *)0xabcd,
		.receive = mock_mm_service_receive
	};
	EFI_GUID guid = {
		0x01234567, 0x89ab, 0xcdef, {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	};
	struct mm_service_call_req req = {
		&guid,
		.req_buf = {
			.data = (uint8_t *)0x1234,
			.data_length = 12,
			.size = 20
		},
		.resp_buf = {
			.data = (uint8_t *)0x2345,
			.data_length = 15,
			.size = 30
		}
	};
	int64_t result = -123456;

	expect_mock_mm_service_receive(&iface, &req, result);
	LONGS_EQUAL(result, mock_mm_service_receive(&iface, &req));
}
