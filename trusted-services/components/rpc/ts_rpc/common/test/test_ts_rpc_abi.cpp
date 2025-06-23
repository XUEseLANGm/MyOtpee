/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../ts_rpc_abi.h"
#include <stdint.h>
#include <string.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(ts_rpc_abi) {
	TEST_SETUP() {
		memset(regs, 0x00, sizeof(regs));
	}

	void set_regs(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4)
	{
		regs[0] = a0;
		regs[1] = a1;
		regs[2] = a2;
		regs[3] = a3;
		regs[4] = a4;
	}

	void check_regs(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4)
	{
		UNSIGNED_LONGS_EQUAL(a0, regs[0]);
		UNSIGNED_LONGS_EQUAL(a1, regs[1]);
		UNSIGNED_LONGS_EQUAL(a2, regs[2]);
		UNSIGNED_LONGS_EQUAL(a3, regs[3]);
		UNSIGNED_LONGS_EQUAL(a4, regs[4]);
	}

	uint32_t regs[5];
};

TEST(ts_rpc_abi, flags)
{
	const uint8_t flags = 0x3f;

	ts_rpc_abi_set_flags(regs, flags);
	check_regs(0x3f000000, 0, 0, 0, 0);

	UNSIGNED_LONGS_EQUAL(flags, ts_rpc_abi_get_flags(regs));
}

TEST(ts_rpc_abi, interface_id)
{
	const uint8_t interface_id = 0xa5;

	ts_rpc_abi_set_interface_id(regs, interface_id);
	check_regs(0x00a50000, 0, 0, 0, 0);

	UNSIGNED_LONGS_EQUAL(interface_id, ts_rpc_abi_get_interface_id(regs));
}

TEST(ts_rpc_abi, management_interface_id)
{
	CHECK_FALSE(ts_rpc_abi_is_management_interface_id(regs));

	ts_rpc_abi_set_management_interface_id(regs);
	check_regs(0x00ff0000, 0, 0, 0, 0);

	CHECK_TRUE(ts_rpc_abi_is_management_interface_id(regs));
}

TEST(ts_rpc_abi, opcode)
{
	const uint16_t opcode = 0x8765;

	ts_rpc_abi_set_opcode(regs, 0x8765);
	check_regs(0x00008765, 0, 0, 0, 0);

	UNSIGNED_LONGS_EQUAL(0x8765, ts_rpc_abi_get_opcode(regs));
}

TEST(ts_rpc_abi, copy_control_reg)
{
	uint32_t source_regs[5] = { 0xfedcba98, 0, 0, 0, 0 };

	ts_rpc_abi_copy_control_reg(regs, source_regs);

	check_regs(0xfedcba98, 0, 0, 0, 0);
}

TEST(ts_rpc_abi, version)
{
	const uint32_t version = 0x98765432;

	ts_rpc_abi_set_version(regs, version);
	check_regs(0, version, 0, 0, 0);

	UNSIGNED_LONGS_EQUAL(version, ts_rpc_abi_get_version(regs));

}

TEST(ts_rpc_abi, memory_handle)
{
	const uint64_t handle = 0xfedcba9876543210;

	ts_rpc_abi_set_memory_handle(regs, handle);
	check_regs(0, 0x76543210, 0xfedcba98, 0, 0);

	UNSIGNED_LONGLONGS_EQUAL(handle, ts_rpc_abi_get_memory_handle(regs));
}

TEST(ts_rpc_abi, memory_tag)
{
	const uint64_t tag = 0xfedcba9876543210;

	ts_rpc_abi_set_memory_tag(regs, tag);
	check_regs(0, 0, 0, 0x76543210, 0xfedcba98);

	UNSIGNED_LONGLONGS_EQUAL(tag, ts_rpc_abi_get_memory_tag(regs));
}

TEST(ts_rpc_abi, rpc_status)
{
	const uint32_t rpc_status = 0x89abcdef;

	ts_rpc_abi_set_rpc_status(regs, rpc_status);
	check_regs(0, rpc_status, 0, 0, 0);

	UNSIGNED_LONGS_EQUAL(rpc_status, ts_rpc_abi_get_rpc_status(regs));
}

TEST(ts_rpc_abi, service_status)
{
	const uint32_t service_status = 0x89abcdef;

	ts_rpc_abi_set_service_status(regs, service_status);
	check_regs(0, 0, service_status, 0, 0);

	UNSIGNED_LONGS_EQUAL(service_status, ts_rpc_abi_get_service_status(regs));
}

TEST(ts_rpc_abi, uuid)
{
	const struct rpc_uuid expected = {
		.uuid = { 0xf0, 0x33, 0xbe, 0x6d, 0x6c, 0xc4, 0x47, 0x38,
			  0x88, 0xfd, 0xdd, 0x44, 0xac, 0x56, 0x2b, 0x69}
	};
	struct rpc_uuid actual = { 0 };

	ts_rpc_abi_set_uuid(regs, &expected);
	check_regs(0, 0x6dbe33f0, 0x3847c46c, 0x44ddfd88, 0x692b56ac);

	ts_rpc_abi_get_uuid(regs, &actual);
	MEMCMP_EQUAL(expected.uuid, actual.uuid, sizeof(expected));
}

TEST(ts_rpc_abi, queried_interface_id)
{
	const uint8_t interface_id = 0xa5;

	ts_rpc_abi_set_queried_interface_id(regs, interface_id);
	check_regs(0, 0, interface_id, 0, 0);

	UNSIGNED_LONGS_EQUAL(interface_id, ts_rpc_abi_get_queried_interface_id(regs));
}

TEST(ts_rpc_abi, request_length)
{
	const uint32_t length = 0x12345678;

	ts_rpc_abi_set_request_length(regs, length);
	check_regs(0, 0, 0, length, 0);

	UNSIGNED_LONGS_EQUAL(length, ts_rpc_abi_get_request_length(regs));
}

TEST(ts_rpc_abi, client_id)
{
	const uint32_t client_id = 0xabcdef01;

	ts_rpc_abi_set_client_id(regs, client_id);
	check_regs(0, 0, 0, 0, client_id);

	UNSIGNED_LONGS_EQUAL(client_id, ts_rpc_abi_get_client_id(regs));
}

TEST(ts_rpc_abi, response_length)
{
	const uint32_t length = 0x12345678;

	ts_rpc_abi_set_response_length(regs, length);
	check_regs(0, 0, 0, length, 0);

	UNSIGNED_LONGS_EQUAL(length, ts_rpc_abi_get_response_length(regs));
}
