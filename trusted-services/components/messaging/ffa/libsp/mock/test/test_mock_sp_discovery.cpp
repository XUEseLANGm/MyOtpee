// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include <CppUTest/TestHarness.h>
#include "mock_sp_discovery.h"
#include <stdint.h>
#include <stdlib.h>




TEST_GROUP(mock_sp_discovery) {
	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().clear();
	}

	static const sp_result result = -1;
};

TEST(mock_sp_discovery, sp_discovery_ffa_version_get)
{
	const uint16_t expected_major = 0xabcd;
	const uint16_t expected_minor = 0xef01;
	uint16_t major = 0, minor = 0;

	expect_sp_discovery_ffa_version_get(&expected_major, &expected_minor,
					    result);
	LONGS_EQUAL(result, sp_discovery_ffa_version_get(&major, &minor));
	UNSIGNED_LONGS_EQUAL(expected_major, major);
	UNSIGNED_LONGS_EQUAL(expected_minor, minor);
}

TEST(mock_sp_discovery, sp_discovery_own_id_get)
{
	const uint16_t expected_id = 0x8765;
	uint16_t id = 0;

	expect_sp_discovery_own_id_get(&expected_id, result);
	LONGS_EQUAL(result, sp_discovery_own_id_get(&id));
	UNSIGNED_LONGS_EQUAL(expected_id, id);
}

TEST(mock_sp_discovery, sp_discovery_partition_id_get)
{
	const struct sp_uuid expected_uuid = {
		.uuid = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
			 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
	const uint16_t expected_id = 0xc1ca;

	struct sp_uuid uuid = expected_uuid;
	uint16_t id = 0;

	expect_sp_discovery_partition_id_get(&expected_uuid, &expected_id,
					       result);
	LONGS_EQUAL(result, sp_discovery_partition_id_get(&uuid, &id));
	UNSIGNED_LONGS_EQUAL(expected_id, id);
}

TEST(mock_sp_discovery, sp_discovery_partition_info_get)
{
	const struct sp_uuid expected_uuid = {
		.uuid = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
			 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
	const struct sp_partition_info expected_info = {
		.partition_id = 0x1234,
		.execution_context_count = 0xffff,
		.supports_direct_requests = true,
		.can_send_direct_requests = true,
		.supports_indirect_requests = false
	};

	struct sp_uuid uuid = expected_uuid;
	struct sp_partition_info info = {0};
	uint32_t in_count = 16;
	uint32_t expected_out_count = 8;
	uint32_t out_count = in_count;


	expect_sp_discovery_partition_info_get(&expected_uuid, &expected_info,
					       in_count, &expected_out_count,
					       result);
	LONGS_EQUAL(result, sp_discovery_partition_info_get(&uuid, &info, &out_count));
	MEMCMP_EQUAL(&expected_info, &info, sizeof(&expected_info));
	UNSIGNED_LONGS_EQUAL(expected_out_count, out_count);
}

TEST(mock_sp_discovery, sp_discovery_partition_info_get_all)
{
	const uint32_t expected_count = 2;
	const struct sp_partition_info expected_info[expected_count] = {{
		.partition_id = 0x5678,
		.execution_context_count = 0x1111,
		.supports_direct_requests = false,
		.can_send_direct_requests = false,
		.supports_indirect_requests = true
	}, {
		.partition_id = 0x1234,
		.execution_context_count = 0xffff,
		.supports_direct_requests = true,
		.can_send_direct_requests = true,
		.supports_indirect_requests = false
	}};

	struct sp_partition_info info[expected_count] = {0};
	uint32_t count = 0;

	expect_sp_discovery_partition_info_get_all(expected_info,
						   &expected_count, result);
	LONGS_EQUAL(result, sp_discovery_partition_info_get_all(info, &count));
	MEMCMP_EQUAL(&expected_info, &info, sizeof(&expected_info));
	UNSIGNED_LONGS_EQUAL(expected_count, count);
}