// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include <string.h>
#include "protocols/common/mm/mm_smc.h"
#include "mock_assert.h"
#include "mock_mm_service.h"
#include "../mm_communicate_call_ep.h"

static uint8_t comm_buffer[4096] __attribute__((aligned(4096)));

TEST_GROUP(mm_communicate_call_ep)
{
	TEST_SETUP()
	{
		mock_mm_service_init();

		memset(comm_buffer, 0x00, sizeof(comm_buffer));
		memset(&call_ep, 0x00, sizeof(call_ep));
		memset(&req_msg, 0x00, sizeof(req_msg));
		memset(&resp_msg, 0x00, sizeof(resp_msg));
	}

	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().removeAllComparatorsAndCopiers();
		mock().clear();
	}

	void check_sp_msg(const struct ffa_direct_msg *msg, uint64_t arg0,
			  uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
	{
		UNSIGNED_LONGLONGS_EQUAL(arg0, msg->args.args64[0]);
		UNSIGNED_LONGLONGS_EQUAL(arg1, msg->args.args64[1]);
		UNSIGNED_LONGLONGS_EQUAL(arg2, msg->args.args64[2]);
		UNSIGNED_LONGLONGS_EQUAL(arg3, msg->args.args64[3]);
		UNSIGNED_LONGLONGS_EQUAL(arg4,  msg->args.args64[4]);
	}

	struct mm_communicate_ep call_ep;
	struct ffa_direct_msg req_msg;
	struct ffa_direct_msg resp_msg;
	EFI_MM_COMMUNICATE_HEADER *header = (EFI_MM_COMMUNICATE_HEADER *)comm_buffer;
	EFI_GUID guid0 =
		{0x01234567, 0x89ab, 0xcdef, {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}};
	EFI_GUID guid1 =
		{0x01234567, 0x89ab, 0xcdef, {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x11}};
};

TEST(mm_communicate_call_ep, init_small_buffer)
{
	CHECK_FALSE(mm_communicate_call_ep_init(NULL, NULL, EFI_MM_COMMUNICATE_HEADER_SIZE - 1));
}

TEST(mm_communicate_call_ep, init)
{
	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
}

TEST(mm_communicate_call_ep, attach_null_guid)
{
	assert_environment_t env;
	struct mm_service_interface *service = (struct mm_service_interface *)1;

	if (SETUP_ASSERT_ENVIRONMENT(env)) {
		mm_communicate_call_ep_attach_service(&call_ep, NULL, service);
	}
}

TEST(mm_communicate_call_ep, attach_null_iface)
{
	assert_environment_t env;
	EFI_GUID *guid = (EFI_GUID *)1;

	if (SETUP_ASSERT_ENVIRONMENT(env)) {
		mm_communicate_call_ep_attach_service(&call_ep, guid, NULL);
	}
}

TEST(mm_communicate_call_ep, attach_one)
{
	EFI_GUID guid = { 0 };
	struct mm_service_interface service = { 0 };

	mm_communicate_call_ep_attach_service(&call_ep, &guid, &service);
}

TEST(mm_communicate_call_ep, attach_two)
{
	EFI_GUID guid = { 0 };
	struct mm_service_interface service = { 0 };

	mm_communicate_call_ep_attach_service(&call_ep, &guid, &service);
	mm_communicate_call_ep_attach_service(&call_ep, &guid, &service);
}

TEST(mm_communicate_call_ep, attach_do_not_fit)
{
	assert_environment_t env;
	EFI_GUID guid = { 0 };
	struct mm_service_interface service = { 0 };

	for (int i = 0; i < MM_COMMUNICATE_MAX_SERVICE_BINDINGS; i++) {
		mm_communicate_call_ep_attach_service(&call_ep, &guid, &service);
	}

	if (SETUP_ASSERT_ENVIRONMENT(env)) {
		mm_communicate_call_ep_attach_service(&call_ep, &guid, &service);
	}
}

TEST(mm_communicate_call_ep, mm_communicate_offset_int_overflow)
{
	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	req_msg.args.args64[0] = 0xffffffffffffffff;

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_INVALID_PARAMETER, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_offset_overflow)
{
	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	req_msg.args.args64[0] = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE + 1;

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_INVALID_PARAMETER, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_length_overflow)
{
	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	header->MessageLength = UINT64_MAX - EFI_MM_COMMUNICATE_HEADER_SIZE + 1;

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_INVALID_PARAMETER, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_too_large)
{
	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	header->MessageLength = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE + 1;

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_INVALID_PARAMETER, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_no_handler)
{
	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	header->MessageLength = 0;

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_NOT_SUPPORTED, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_single_handler_not_matching)
{
	struct mm_service_interface iface = { 0 };

	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	mm_communicate_call_ep_attach_service(&call_ep, &guid0, &iface);
	header->MessageLength = 0;

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_NOT_SUPPORTED, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_single_handler_matching)
{
	const size_t req_len = 16;
	struct mm_service_interface iface = {
		.context = (void *)0x1234,
		.receive = mock_mm_service_receive
	};
	struct mm_service_call_req req = {
		.guid = &guid0,
		.req_buf = {
			.data = header->Data,
			.data_length = req_len,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE
		},
		.resp_buf = {
			.data = header->Data,
			.data_length = 0,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE
		},
	};

	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	mm_communicate_call_ep_attach_service(&call_ep, &guid0, &iface);

	memcpy(&header->HeaderGuid, &guid0, sizeof(guid0));
	header->MessageLength = req_len;

	expect_mock_mm_service_receive(&iface, &req, MM_RETURN_CODE_SUCCESS);

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_SUCCESS, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_single_handler_matching_with_offset)
{
	const size_t offset = 0x10;
	EFI_MM_COMMUNICATE_HEADER *header = (EFI_MM_COMMUNICATE_HEADER *)(comm_buffer + offset);

	const size_t req_len = 16;
	struct mm_service_interface iface = {
		.context = (void *)0x1234,
		.receive = mock_mm_service_receive
	};
	struct mm_service_call_req req = {
		.guid = &guid0,
		.req_buf = {
			.data = header->Data,
			.data_length = req_len,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE - offset
		},
		.resp_buf = {
			.data = header->Data,
			.data_length = 0,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE - offset
		},
	};

	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	mm_communicate_call_ep_attach_service(&call_ep, &guid0, &iface);

	memcpy(&header->HeaderGuid, &guid0, sizeof(guid0));
	header->MessageLength = req_len;
	req_msg.args.args64[0] = offset;

	expect_mock_mm_service_receive(&iface, &req, MM_RETURN_CODE_SUCCESS);

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_SUCCESS, 0, 0, 0, 0);
}


TEST(mm_communicate_call_ep, mm_communicate_single_handler_matching_error)
{
	const size_t req_len = 16;
	struct mm_service_interface iface = {
		.context = (void *)0x1234,
		.receive = mock_mm_service_receive
	};
	struct mm_service_call_req req = {
		.guid = &guid0,
		.req_buf = {
			.data = header->Data,
			.data_length = req_len,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE
		},
		.resp_buf = {
			.data = header->Data,
			.data_length = 0,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE
		},
	};

	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	mm_communicate_call_ep_attach_service(&call_ep, &guid0, &iface);

	memcpy(&header->HeaderGuid, &guid0, sizeof(guid0));
	header->MessageLength = req_len;

	expect_mock_mm_service_receive(&iface, &req, MM_RETURN_CODE_NO_MEMORY);

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_NO_MEMORY, 0, 0, 0, 0);
}

TEST(mm_communicate_call_ep, mm_communicate_two_handlers)
{
	const size_t req_len = 16;
	struct mm_service_interface iface0 = {
		.context = (void *)0x1234,
		.receive = mock_mm_service_receive
	};
	struct mm_service_interface iface1 = {
		.context = (void *)0x1235,
		.receive = mock_mm_service_receive
	};
	struct mm_service_call_req req = {
		.guid = &guid1,
		.req_buf = {
			.data = header->Data,
			.data_length = req_len,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE
		},
		.resp_buf = {
			.data = header->Data,
			.data_length = 0,
			.size = sizeof(comm_buffer) - EFI_MM_COMMUNICATE_HEADER_SIZE
		},
	};

	CHECK_TRUE(mm_communicate_call_ep_init(&call_ep, comm_buffer, sizeof(comm_buffer)));
	mm_communicate_call_ep_attach_service(&call_ep, &guid0, &iface0);
	mm_communicate_call_ep_attach_service(&call_ep, &guid1, &iface1);

	memcpy(&header->HeaderGuid, &guid1, sizeof(guid0));
	header->MessageLength = req_len;

	expect_mock_mm_service_receive(&iface1, &req, MM_RETURN_CODE_SUCCESS);

	mm_communicate_call_ep_receive(&call_ep, &req_msg, &resp_msg);

	check_sp_msg(&resp_msg, MM_RETURN_CODE_SUCCESS, 0, 0, 0, 0);
}
