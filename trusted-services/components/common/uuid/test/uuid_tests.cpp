/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstring>
#include <common/uuid/uuid.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(UuidTests) {

};

TEST(UuidTests, parseValidUuidLowerCase) {

	/* A valid UUID using lower-case */
	const char *uuid_text = "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0";
	CHECK(uuid_is_valid(uuid_text));

	const uint8_t expected_bytes[] =
		{0xd9,0xdf,0x52,0xd5,
			0x16,0xa2,
			0x4b,0xb2,
			0x9a,0xa4,
			0xd2,0x6d,0x3b,0x84,0xe8,0xc0};

	uint8_t byte_array[UUID_OCTETS_LEN];
	memset(byte_array, 0, sizeof(byte_array));

	CHECK(uuid_parse_to_octets(uuid_text, byte_array, sizeof(byte_array)));
	CHECK(memcmp(byte_array, expected_bytes, UUID_OCTETS_LEN) == 0);
}

TEST(UuidTests, parseValidUuidMixedCase) {

	/* A valid UUID using mixed-case */
	const char *uuid_text = "D9df52d5-16a2-4bB2-9aa4-d26d3b84E8c0";
	CHECK(uuid_is_valid(uuid_text));

	const uint8_t expected_bytes[] =
		{0xd9,0xdf,0x52,0xd5,
			0x16,0xa2,
			0x4b,0xb2,
			0x9a,0xa4,
			0xd2,0x6d,0x3b,0x84,0xe8,0xc0};

	uint8_t byte_array[UUID_OCTETS_LEN];
	memset(byte_array, 0, sizeof(byte_array));

	CHECK(uuid_parse_to_octets(uuid_text, byte_array, sizeof(byte_array)));
	CHECK(memcmp(byte_array, expected_bytes, UUID_OCTETS_LEN) == 0);
}

TEST(UuidTests, parseUuidInUrn) {

	/* A valid UUID embedded in a urn */
	const char *urn_text = "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66:0";
	CHECK(uuid_is_valid(&urn_text[9]));

	const uint8_t expected_bytes[] =
		{0x6e,0x8b,0xc4,0x30,
			0x9c,0x3a,
			0x11,0xd9,
			0x96,0x69,
			0x08,0x00,0x20,0x0c,0x9a,0x66};

	uint8_t byte_array[UUID_OCTETS_LEN];
	memset(byte_array, 0, sizeof(byte_array));

	CHECK(uuid_parse_to_octets(&urn_text[9], byte_array, sizeof(byte_array)));
	CHECK(memcmp(byte_array, expected_bytes, UUID_OCTETS_LEN) == 0);
}

TEST(UuidTests, parseError) {

	/* Invalid digit */
	const char *broken1 = "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8X0";
	CHECK(!uuid_is_valid(broken1));

	/* Invalid separator */
	const char *broken2 = "d9df52d5-16a2-4bb2-9aa4_d26d3b84e8c0";
	CHECK(!uuid_is_valid(broken2));

	/* Too short */
	const char *broken3 = "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c";
	CHECK(!uuid_is_valid(broken3));

	/* Zero length */
	const char *broken4 = "";
	CHECK(!uuid_is_valid(broken4));
}

TEST(UuidTests, parseValidUuidToGuidOctets) {

	/* A valid UUID using lower-case */
	const char *uuid_text = "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0";
	CHECK(uuid_is_valid(uuid_text));

	/* GUID octet representation is expected to be */
	const uint8_t expected_bytes[] =
		{0xd5,0x52,0xdf,0xd9,
			0xa2,0x16,
			0xb2,0x4b,
			0x9a,0xa4,
			0xd2,0x6d,0x3b,0x84,0xe8,0xc0};

	uint8_t byte_array[UUID_OCTETS_LEN];
	memset(byte_array, 0, sizeof(byte_array));

	CHECK(uuid_parse_to_guid_octets(uuid_text, byte_array, sizeof(byte_array)));
	CHECK(memcmp(byte_array, expected_bytes, UUID_OCTETS_LEN) == 0);
}

TEST(UuidTests, checkOctetsFromCanonical) {

	/* A valid UUID */
	const char *uuid_text = "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0";
	CHECK(uuid_is_valid(uuid_text));

	struct uuid_octets result1;

	memset(&result1, 0x22, sizeof(result1));
	uuid_octets_from_canonical(&result1, uuid_text);

	struct uuid_octets result2;

	memset(&result2, 0xaa, sizeof(result2));
	size_t valid_chars = uuid_parse_to_octets(uuid_text,
		result2.octets, sizeof(result2.octets));

	UNSIGNED_LONGS_EQUAL(UUID_CANONICAL_FORM_LEN, valid_chars);
	MEMCMP_EQUAL(result2.octets, result1.octets, sizeof(result2.octets));
}

TEST(UuidTests, checkIsEqualOperation) {

	struct uuid_octets uuid_a;
	struct uuid_octets uuid_b;

	uuid_guid_octets_from_canonical(&uuid_a, "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0");
	uuid_guid_octets_from_canonical(&uuid_b, "2435fa44-0951-4ce9-bcf4-1ad08d77cbff");

	CHECK_FALSE(uuid_is_equal(uuid_a.octets, uuid_b.octets));
	CHECK_TRUE(uuid_is_equal(uuid_a.octets, uuid_a.octets));
	CHECK_TRUE(uuid_is_equal(uuid_b.octets, uuid_b.octets));
}

TEST(UuidTests, checkNilUuidOperations) {

	struct uuid_octets uuid;

	uuid_guid_octets_from_canonical(&uuid, "00000000-0000-0000-0000-000000000000");
	CHECK_TRUE(uuid_is_equal(uuid_get_nil()->octets, uuid.octets));
	CHECK_TRUE(uuid_is_nil(uuid.octets));

	uuid_guid_octets_from_canonical(&uuid, "00000000-0000-0000-0000-000000000003");
	CHECK_FALSE(uuid_is_nil(uuid.octets));
}

TEST(UuidTests, roundTrip) {

	/* A valid UUID using lower-case */
	const char *uuid_text = "d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0";
	CHECK_TRUE(uuid_is_valid(uuid_text));

	struct uuid_octets uuid;
	struct uuid_canonical canonical_uuid;

	/* Round trip using standard octet order */
	uuid_octets_from_canonical(&uuid, uuid_text);
	uuid_canonical_from_octets(&canonical_uuid, &uuid);

	MEMCMP_EQUAL(uuid_text, canonical_uuid.characters, sizeof(canonical_uuid.characters));

	/* Round trip using GUID octet order */
	uuid_guid_octets_from_canonical(&uuid, uuid_text);
	uuid_canonical_from_guid_octets(&canonical_uuid, &uuid);

	MEMCMP_EQUAL(uuid_text, canonical_uuid.characters, sizeof(canonical_uuid.characters));
}