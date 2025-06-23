// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include <CppUTest/TestHarness.h>
#include "mock_sp_memory_management.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const struct sp_memory_descriptor expected_descriptor = {
	.sender_id = 0xfedc,
	.memory_type = sp_memory_type_normal_memory,
	.mem_region_attr = {.normal_memory = {
		.cacheability = sp_cacheability_write_back,
		.shareability = sp_shareability_inner_shareable
	}},
	.flags = {
		.zero_memory = true,
		.operation_time_slicing = true,
		.zero_memory_after_relinquish = true,
		.transaction_type = sp_memory_transaction_type_relayer_specified,
		.alignment_hint = 0x2000
	},
	.tag = 0x0123456789abcdefULL
};
static const struct sp_memory_access_descriptor expected_acc_desc[] = {
	{
		.receiver_id = 0xfafa,
		.instruction_access = sp_instruction_access_executable,
		.data_access = sp_data_access_read_only
	}, {
		.receiver_id = 0xc1ca,
		.instruction_access = sp_instruction_access_not_executable,
		.data_access = sp_data_access_read_write
	}
};
static const struct sp_memory_region expected_regions[2] = {
	{.address = (void *)0x01234567, .page_count = 0x89abcdef},
	{.address = (void *)0x12345670, .page_count = 0x9abcdef8},
};
static const uint64_t expected_handle = 0xabcdef0123456789ULL;
static const void *expected_address = (const void *)0x234567879;
static const struct sp_mem_perm expected_mem_perm = {
	.data_access = sp_mem_perm_data_perm_read_write,
	.instruction_access = sp_mem_perm_instruction_perm_non_executable,
};

TEST_GROUP(mock_sp_memory_management)
{
	TEST_SETUP()
	{
		memset(&descriptor, 0x00, sizeof(descriptor));
		memset(&acc_desc, 0x00, sizeof(acc_desc));
		memset(&regions, 0x00, sizeof(regions));
		handle = 0;
		supported = false;
	}

	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().clear();
	}

	struct sp_memory_descriptor descriptor;
	struct sp_memory_access_descriptor acc_desc[2];
	struct sp_memory_region regions[2];
	uint64_t handle;
	bool supported;
	struct ffa_mem_transaction_buffer tr_buffer;

	static const sp_result result = -1;
};

TEST(mock_sp_memory_management, sp_memory_donate)
{
	descriptor = expected_descriptor;
	acc_desc[0] = expected_acc_desc[0];
	memcpy(regions, expected_regions, sizeof(regions));

	expect_sp_memory_donate(&expected_descriptor, expected_acc_desc, expected_regions, 2,
				&expected_handle, result);
	LONGS_EQUAL(result, sp_memory_donate(&descriptor, acc_desc, regions, 2, &handle));

	UNSIGNED_LONGLONGS_EQUAL(expected_handle, handle);
}

TEST(mock_sp_memory_management, sp_memory_donate_dynamic)
{
	descriptor = expected_descriptor;
	acc_desc[0] = expected_acc_desc[0];
	memcpy(regions, expected_regions, sizeof(regions));

	expect_sp_memory_donate_dynamic(&expected_descriptor, expected_acc_desc, expected_regions,
					2, &expected_handle, result);
	LONGS_EQUAL(result, sp_memory_donate_dynamic(&descriptor, acc_desc, regions, 2, &handle,
						     &tr_buffer));

	UNSIGNED_LONGLONGS_EQUAL(expected_handle, handle);
}

TEST(mock_sp_memory_management, sp_memory_donate_dynamic_is_supported)
{
	const bool expected_supported = true;
	expect_sp_memory_donate_dynamic_is_supported(&expected_supported, result);
	LONGS_EQUAL(result, sp_memory_donate_dynamic_is_supported(&supported));
	CHECK_TRUE(supported);
}

TEST(mock_sp_memory_management, sp_memory_lend)
{
	descriptor = expected_descriptor;
	memcpy(acc_desc, expected_acc_desc, sizeof(acc_desc));
	memcpy(regions, expected_regions, sizeof(regions));

	expect_sp_memory_lend(&descriptor, acc_desc, 2, regions, 2, &expected_handle, result);
	LONGS_EQUAL(result, sp_memory_lend(&descriptor, acc_desc, 2, regions, 2, &handle));
	UNSIGNED_LONGLONGS_EQUAL(expected_handle, handle);
}

TEST(mock_sp_memory_management, sp_memory_lend_dynamic)
{
	descriptor = expected_descriptor;
	memcpy(acc_desc, expected_acc_desc, sizeof(acc_desc));
	memcpy(regions, expected_regions, sizeof(regions));

	expect_sp_memory_lend_dynamic(&descriptor, acc_desc, 2, regions, 2, &expected_handle,
				      result);
	LONGS_EQUAL(result, sp_memory_lend_dynamic(&descriptor, acc_desc, 2, regions, 2, &handle,
						   &tr_buffer));
	UNSIGNED_LONGLONGS_EQUAL(expected_handle, handle);
}

TEST(mock_sp_memory_management, sp_memory_lend_dynamic_is_supported)
{
	const bool expected_supported = true;
	expect_sp_memory_lend_dynamic_is_supported(&expected_supported, result);
	LONGS_EQUAL(result, sp_memory_lend_dynamic_is_supported(&supported));
	CHECK_TRUE(supported);
}

TEST(mock_sp_memory_management, sp_memory_share)
{
	descriptor = expected_descriptor;
	memcpy(acc_desc, expected_acc_desc, sizeof(acc_desc));
	memcpy(regions, expected_regions, sizeof(regions));

	expect_sp_memory_share(&descriptor, acc_desc, 2, regions, 2, &expected_handle, result);
	LONGS_EQUAL(result, sp_memory_share(&descriptor, acc_desc, 2, regions, 2, &handle));
	UNSIGNED_LONGLONGS_EQUAL(expected_handle, handle);
}

TEST(mock_sp_memory_management, sp_memory_share_dynamic)
{
	descriptor = expected_descriptor;
	memcpy(acc_desc, expected_acc_desc, sizeof(acc_desc));
	memcpy(regions, expected_regions, sizeof(regions));

	expect_sp_memory_share_dynamic(&descriptor, acc_desc, 2, regions, 2, &expected_handle,
				      result);
	LONGS_EQUAL(result, sp_memory_share_dynamic(&descriptor, acc_desc, 2, regions, 2, &handle,
						   &tr_buffer));
	UNSIGNED_LONGLONGS_EQUAL(expected_handle, handle);
}

TEST(mock_sp_memory_management, sp_memory_share_dynamic_is_supported)
{
	const bool expected_supported = true;
	expect_sp_memory_share_dynamic_is_supported(&expected_supported, result);
	LONGS_EQUAL(result, sp_memory_share_dynamic_is_supported(&supported));
	CHECK_TRUE(supported);
}

TEST(mock_sp_memory_management, sp_memory_retrieve)
{
	const uint32_t expected_region_count = 1;
	struct sp_memory_access_descriptor acc_desc = expected_acc_desc[0];
	struct sp_memory_region region = expected_regions[0];
	uint32_t out_region_count = 0;

	descriptor = expected_descriptor;

	expect_sp_memory_retrieve(&expected_descriptor, &expected_acc_desc[0],
				  &expected_acc_desc[1], &expected_regions[0],
				  &expected_regions[1], 1, &expected_region_count, expected_handle,
				  result);
	LONGS_EQUAL(result, sp_memory_retrieve(&descriptor, &acc_desc, &region, 1,
					       &out_region_count, expected_handle));
	MEMCMP_EQUAL(&acc_desc, &expected_acc_desc[1], sizeof(acc_desc));
	MEMCMP_EQUAL(&region, &expected_regions[1], sizeof(region));
	UNSIGNED_LONGS_EQUAL(expected_region_count, out_region_count);
}

TEST(mock_sp_memory_management, sp_memory_retrieve_dynamic)
{
	const uint32_t expected_region_count = 1;
	struct sp_memory_access_descriptor acc_desc = expected_acc_desc[0];
	struct sp_memory_region region = expected_regions[0];
	uint32_t out_region_count = 0;

	descriptor = expected_descriptor;

	expect_sp_memory_retrieve_dynamic(&expected_descriptor, &expected_acc_desc[0],
					  &expected_acc_desc[1], &expected_regions[0],
					  &expected_regions[1], 1, &expected_region_count,
					  expected_handle, result);
	LONGS_EQUAL(result, sp_memory_retrieve_dynamic(&descriptor, &acc_desc, &region, 1,
						       &out_region_count, expected_handle,
						       &tr_buffer));
	MEMCMP_EQUAL(&acc_desc, &expected_acc_desc[1], sizeof(acc_desc));
	MEMCMP_EQUAL(&region, &expected_regions[1], sizeof(region));
	UNSIGNED_LONGS_EQUAL(expected_region_count, out_region_count);
}

TEST(mock_sp_memory_management, sp_memory_retrieve_dynamic_is_supported)
{
	const bool expected_supported = true;
	expect_sp_memory_retrieve_dynamic_is_supported(&expected_supported, result);
	LONGS_EQUAL(result, sp_memory_retrieve_dynamic_is_supported(&supported));
	CHECK_TRUE(supported);
}

TEST(mock_sp_memory_management, sp_memory_relinquish)
{
	uint16_t endpoints[3] = {1, 2, 3};
	struct sp_memory_transaction_flags flags = {0}; // TODO: flags

	expect_sp_memory_relinquish(expected_handle, endpoints, 3, &flags, result);
	LONGS_EQUAL(result, sp_memory_relinquish(expected_handle, endpoints, 3, &flags));
}

TEST(mock_sp_memory_management, sp_memory_reclaim)
{
	uint32_t flags = 0xffffffff;

	expect_sp_memory_reclaim(expected_handle, flags, result);
	LONGS_EQUAL(result, sp_memory_reclaim(expected_handle, flags));
}

TEST(mock_sp_memory_management, sp_memory_permission_get)
{
	struct sp_mem_perm mem_perm;

	memset(&mem_perm, 0x00, sizeof(mem_perm));

	expect_sp_memory_permission_get(expected_address, &expected_mem_perm, result);
	LONGS_EQUAL(result, sp_memory_permission_get(expected_address, &mem_perm));
	MEMCMP_EQUAL(&expected_mem_perm, &mem_perm, sizeof(expected_mem_perm));
}

TEST(mock_sp_memory_management, sp_memory_permission_set)
{
	size_t size = 0x7654;

	expect_sp_memory_permission_set(expected_address, size, &expected_mem_perm, result);
	LONGS_EQUAL(result, sp_memory_permission_set(expected_address, size, &expected_mem_perm));
}
