/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <cstring>
#include <CppUTest/TestHarness.h>
#include <psa/internal_trusted_storage.h>
#include "its_api_tests.h"

void its_api_tests::storeNewItem()
{
    psa_status_t status;
    psa_storage_uid_t uid = 10;
    struct psa_storage_info_t storage_info;
    static const size_t ITEM_SIZE = 68;
    uint8_t item[ITEM_SIZE];
    uint8_t read_item[ITEM_SIZE];

    memset(item, 0x55, sizeof(item));

    /* Probe to check item does not exist */
    status = psa_its_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);

    /* Store the item */
    status = psa_its_set(uid, sizeof(item), item, PSA_STORAGE_FLAG_NONE);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* Probe to check item now exists */
    status = psa_its_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_SUCCESS, status);
    CHECK_EQUAL(sizeof(item), storage_info.size);

    /* Get the item */
    size_t read_len = 0;
    status = psa_its_get(uid, 0, sizeof(read_item), read_item, &read_len);
    CHECK_EQUAL(PSA_SUCCESS, status);
    CHECK_EQUAL(sizeof(item), read_len);
    CHECK(memcmp(item, read_item, sizeof(item)) == 0);

    /* Remove the item */
    status = psa_its_remove(uid);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* Expect it to have gone */
    status = psa_its_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);
}

void its_api_tests::storageLimitTest(size_t size_limit)
{
    psa_status_t status;
    psa_storage_uid_t uid = 10;
    struct psa_storage_info_t storage_info;
    static const size_t MAX_ITEM_SIZE = 10000;
    uint8_t item[MAX_ITEM_SIZE];

    memset(item, 0x55, sizeof(item));

    /* Probe to check item does not exist */
    status = psa_its_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);

    /* Attempt to store an item that just exceeds the store's limit*/
    status = psa_its_set(uid, size_limit + 1, item, PSA_STORAGE_FLAG_NONE);
    CHECK(PSA_SUCCESS != status);

    /* Attempt to store a stupidly big item */
    status = psa_its_set(uid, static_cast<size_t>(-1), item, PSA_STORAGE_FLAG_NONE);
    CHECK(PSA_SUCCESS != status);

    /* Attempt to store a zero length item */
    status = psa_its_set(uid, 0, item, PSA_STORAGE_FLAG_NONE);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* Remove the item */
    status = psa_its_remove(uid);
    CHECK_EQUAL(PSA_SUCCESS, status);
}
