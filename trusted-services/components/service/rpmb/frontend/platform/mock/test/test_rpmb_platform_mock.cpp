/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include "../rpmb_platform_mock.h"
#include <string.h>

TEST_GROUP(rpmb_platform_mock) {
	TEST_SETUP()
	{
		platform = rpmb_platform_mock_init(&platform_mock);
	}

	TEST_TEARDOWN()
	{
		rpmb_platform_mock_deinit(&platform_mock);

		mock().checkExpectations();
		mock().clear();
	}

	struct rpmb_platform *platform;
	struct rpmb_platform_mock platform_mock;
	const uint32_t dev_id = 1;
};

TEST(rpmb_platform_mock, derive_key)
{
	const uint8_t data[4] = { 1, 2, 3, 4};
	const uint8_t expected_key[4] = { 5, 6, 7, 8};
	uint8_t key[4] = { 0 };

	rpmb_platform_mock_expect_derive_key(platform, data, sizeof(data), expected_key,
					     sizeof(expected_key), PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, platform->interface->derive_key(platform, data, sizeof(data),
								 key, sizeof(key)));
	MEMCMP_EQUAL(expected_key, key, sizeof(expected_key));
}

TEST(rpmb_platform_mock, get_nonce)
{
	const uint8_t expected_nonce[4] = { 5, 6, 7, 8};
	uint8_t nonce[4] = { 0 };

	rpmb_platform_mock_expect_get_nonce(platform, expected_nonce, sizeof(expected_nonce),
					    PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, platform->interface->get_nonce(platform, nonce, sizeof(nonce)));
	MEMCMP_EQUAL(expected_nonce, nonce, sizeof(expected_nonce));
}

TEST(rpmb_platform_mock, calculate_mac)
{
	const uint8_t key[4] = { 1, 2, 3, 4 };
	struct rpmb_data_frame frames[3] = { 0 };
	const uint8_t expected_mac[4] = { 5, 6, 7, 8 };
	uint8_t mac[4] = { 0 };

	memset(frames, 0x5a, sizeof(frames));


	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), frames, 3, expected_mac,
						sizeof(expected_mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, platform->interface->calculate_mac(platform, key, sizeof(key),
								    frames, 3, mac, sizeof(mac)));
	MEMCMP_EQUAL(expected_mac, mac, sizeof(expected_mac));
}