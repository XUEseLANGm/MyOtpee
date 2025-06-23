/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/crc32/crc32.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(Crc32Tests)
{
	TEST_SETUP()
	{
		crc32_init();
	}
};

/*
 * Expected results obtained from: https://crc32.online/
 */
TEST(Crc32Tests, shortString)
{
	const unsigned char test_input[] = "Hello";
	uint32_t expected_result = 0xf7d18982;
	uint32_t input_crc = 0;

	uint32_t result = crc32(input_crc, test_input, sizeof(test_input) - 1);

	UNSIGNED_LONGS_EQUAL(expected_result, result);
}

TEST(Crc32Tests, longString)
{
	const unsigned char test_input[] =
		"The boy stood on the burning deck Whence all but he had fled";
	uint32_t expected_result = 0x1f11704c;
	uint32_t input_crc = 0;

	uint32_t result = crc32(input_crc, test_input, sizeof(test_input) - 1);

	UNSIGNED_LONGS_EQUAL(expected_result, result);
}

TEST(Crc32Tests, multiPart)
{
	const unsigned char test_input_1[] =
		"The boy stood on the burning deck ";
	const unsigned char test_input_2[] =
		"Whence all but he had fled";

	uint32_t expected_result = 0x1f11704c;
	uint32_t result = 0;

	result = crc32(result, test_input_1, sizeof(test_input_1) - 1);
	result = crc32(result, test_input_2, sizeof(test_input_2) - 1);

	UNSIGNED_LONGS_EQUAL(expected_result, result);
}