/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstring>
#include <common/tlv/tlv.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(TlvTests)
{

};

TEST(TlvTests, decodeGoodRecords)
{
    struct tlv_const_iterator iter;
    struct tlv_record decoded_record;

    /* Case 1: Valid single zero length record */
    const uint8_t case_1[] = {
        0x77, 0x31, 0x00, 0x00
    };

    tlv_const_iterator_begin(&iter, case_1, sizeof(case_1));
    CHECK_TRUE(tlv_decode(&iter, &decoded_record));
    UNSIGNED_LONGS_EQUAL(0x7731, decoded_record.tag);
    UNSIGNED_LONGS_EQUAL(0, decoded_record.length);
    CHECK_FALSE(tlv_decode(&iter, &decoded_record));

    /* Case 2: Two valid records */
    const uint8_t case_2[] = {
        0x01, 0x10, 0x00, 0x01, 0x50,
        0x02, 0x11, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04
    };

    tlv_const_iterator_begin(&iter, case_2, sizeof(case_2));
    CHECK_TRUE(tlv_decode(&iter, &decoded_record));
    UNSIGNED_LONGS_EQUAL(0x0110, decoded_record.tag);
    UNSIGNED_LONGS_EQUAL(1, decoded_record.length);
    UNSIGNED_LONGS_EQUAL(0x50, decoded_record.value[0]);
    CHECK_TRUE(tlv_decode(&iter, &decoded_record));
    UNSIGNED_LONGS_EQUAL(0x0211, decoded_record.tag);
    UNSIGNED_LONGS_EQUAL(4, decoded_record.length);
    UNSIGNED_LONGS_EQUAL(0x01, decoded_record.value[0]);
    UNSIGNED_LONGS_EQUAL(0x02, decoded_record.value[1]);
    UNSIGNED_LONGS_EQUAL(0x03, decoded_record.value[2]);
    UNSIGNED_LONGS_EQUAL(0x04, decoded_record.value[3]);
    CHECK_FALSE(tlv_decode(&iter, &decoded_record));
}

TEST(TlvTests, findAndDecode)
{
    struct tlv_const_iterator iter;
    struct tlv_record decoded_record;

    /*
     * Checks use of the tlv_find_decode method to extract known records
     * from a sequence of records, encoded in ascending tag order, that includes
     * ones that the receiver isn't interested in.
     */
    const uint8_t encoded_records[] = {
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x03, 0x88, 0x88, 0x88,
        0x00, 0x07, 0x00, 0x02, 0x77, 0x77,
        0x00, 0x09, 0x00, 0x01, 0x77
    };

    tlv_const_iterator_begin(&iter, encoded_records, sizeof(encoded_records));
    CHECK_TRUE(tlv_find_decode(&iter, 0x0001, &decoded_record));
    UNSIGNED_LONGS_EQUAL(0, decoded_record.length);
    CHECK_TRUE(tlv_find_decode(&iter, 0x0007, &decoded_record));
    UNSIGNED_LONGS_EQUAL(2, decoded_record.length);
    CHECK_TRUE(tlv_find_decode(&iter, 0x0009, &decoded_record));
    UNSIGNED_LONGS_EQUAL(1, decoded_record.length);
}

TEST(TlvTests, findAndDecodeMissingOptional)
{
    struct tlv_const_iterator iter;
    struct tlv_record decoded_record;

    /*
     * Checks finding a missing record is correctly
     * identified as not present but that the following
     * record is found.
     */
    const uint8_t encoded_records[] = {
        0x00, 0x07, 0x00, 0x02, 0x77, 0x77
    };

    tlv_const_iterator_begin(&iter, encoded_records, sizeof(encoded_records));
    CHECK(!tlv_find_decode(&iter, 0x0001, &decoded_record));
    CHECK(tlv_find_decode(&iter, 0x0007, &decoded_record));
    CHECK_EQUAL(2, decoded_record.length);
}

TEST(TlvTests, decodeBadRecords)
{
    struct tlv_const_iterator iter;
    struct tlv_record decoded_record;

    /* Case 1: Too short to accommodate a valid header */
    const uint8_t case_1[] = {
        0x77, 0x31, 0x00
    };

    tlv_const_iterator_begin(&iter, case_1, sizeof(case_1));
    CHECK_FALSE(tlv_decode(&iter, &decoded_record));

    /* Case 1: A complete record followed by a truncated one */
    const uint8_t case_2[] = {
        0x77, 0x31, 0x00, 0x00,
        0x03, 0x21, 0x00, 0x03, 0xaa
    };

    tlv_const_iterator_begin(&iter, case_2, sizeof(case_2));
    CHECK_TRUE(tlv_decode(&iter, &decoded_record));
    CHECK_FALSE(tlv_decode(&iter, &decoded_record));
}

TEST(TlvTests, encodeRecords)
{
    struct tlv_iterator iter;
    struct tlv_record record_to_encode;
    size_t required_space;

    /* Case 1: Encode zero length record */
    const uint8_t case_1_expected[] = {
        0x66, 0x77, 0x00, 0x00
    };
    record_to_encode.tag = 0x6677;
    record_to_encode.length = 0;
    record_to_encode.value = NULL;
    required_space = tlv_required_space(record_to_encode.length);
    uint8_t case_1_actual[required_space];
    tlv_iterator_begin(&iter, case_1_actual, required_space);
    CHECK_TRUE(tlv_encode(&iter, &record_to_encode));
    MEMCMP_EQUAL(case_1_expected, case_1_actual, required_space);

    /* Case 2: Encode two records */
    const uint8_t case_2_expected[] = {
        0xa8, 0xa9, 0x00, 0x01, 0x88,
        0xa8, 0xaa, 0x00, 0x02, 0x01, 0x02
    };

    required_space = tlv_required_space(1) + tlv_required_space(2);
    uint8_t case_2_actual[required_space];
    tlv_iterator_begin(&iter, case_2_actual, required_space);

    record_to_encode.tag = 0xa8a9;
    record_to_encode.length = 1;
    record_to_encode.value = &case_2_expected[4];
    CHECK_TRUE(tlv_encode(&iter, &record_to_encode));

    record_to_encode.tag = 0xa8aa;
    record_to_encode.length = 2;
    record_to_encode.value = &case_2_expected[9];
    CHECK_TRUE(tlv_encode(&iter, &record_to_encode));

    MEMCMP_EQUAL(case_2_expected, case_2_actual, required_space);

    /* Check that you can't encode beyond the limit of the buffer */
    CHECK_FALSE(tlv_encode(&iter, &record_to_encode));
}

TEST(TlvTests, encodeInsufficientSpace)
{
    struct tlv_iterator iter;
    struct tlv_record record_to_encode;
    size_t required_space;

    /* Case 1: Encode record into buffer that isn't big enough */
    const uint8_t case_1_expected[] = {
        0x66, 0x77, 0x00, 0x03, 0x01, 0x02, 0x03
    };
    record_to_encode.tag = 0x6677;
    record_to_encode.length = 3;
    record_to_encode.value = &case_1_expected[4];
    required_space = tlv_required_space(record_to_encode.length) - 1;
    uint8_t case_1_actual[required_space];
    tlv_iterator_begin(&iter, case_1_actual, required_space);
    CHECK_FALSE(tlv_encode(&iter, &record_to_encode));
}

TEST(TlvTests, encodeWrongOrder)
{
    struct tlv_iterator iter;
    struct tlv_record record_to_encode;
    size_t required_space;

    /* Check defence against encoding successive records
     * out of tag value order.  Encoding rules require
     * records to be in ascending tag value order.
     */
    const uint8_t record_value[] = {
        0x11, 0x22, 0x33, 0x44
    };

    /* Attemps to encode 4 records, the first 3 obey order
     * rule, the last one doesn't
     */
    required_space = tlv_required_space(sizeof(record_value)) * 4;
    uint8_t encode_buffer[required_space];
    tlv_iterator_begin(&iter, encode_buffer, required_space);

    record_to_encode.tag = 1;
    record_to_encode.length = sizeof(record_value);
    record_to_encode.value = record_value;
    CHECK_TRUE(tlv_encode(&iter, &record_to_encode));

    record_to_encode.tag = 2;
    record_to_encode.length = sizeof(record_value);
    record_to_encode.value = record_value;
    CHECK_TRUE(tlv_encode(&iter, &record_to_encode));

    record_to_encode.tag = 2;
    record_to_encode.length = sizeof(record_value);
    record_to_encode.value = record_value;
    CHECK_TRUE(tlv_encode(&iter, &record_to_encode));

    record_to_encode.tag = 1;
    record_to_encode.length = sizeof(record_value);
    record_to_encode.value = record_value;
    CHECK_FALSE(tlv_encode(&iter, &record_to_encode));
}
