/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <cstring>
#include <CppUTest/TestHarness.h>
#include <psa/protected_storage.h>
#include "ps_api_tests.h"

/**
 * Creates a new slot and sets its contents in one go.  Uses
 * mandatory PS API operations only.
 */
void ps_api_tests::set()
{
    psa_status_t status;
    psa_storage_uid_t uid = 10;
    struct psa_storage_info_t storage_info;
    static const size_t ITEM_SIZE = 68;
    uint8_t item[ITEM_SIZE];
    uint8_t read_item[ITEM_SIZE];

    memset(item, 0x55, sizeof(item));

    /* Probe to check item does not exist */
    status = psa_ps_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);

    /* Store the item */
    status = psa_ps_set(uid, sizeof(item), item, PSA_STORAGE_FLAG_NONE);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* Probe to check item now exists */
    status = psa_ps_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_SUCCESS, status);
    CHECK_EQUAL(sizeof(item), storage_info.size);

    /* Get the item */
    size_t read_len = 0;
    status = psa_ps_get(uid, 0, sizeof(read_item), read_item, &read_len);
    CHECK_EQUAL(PSA_SUCCESS, status);
    CHECK_EQUAL(sizeof(item), read_len);
    CHECK(memcmp(item, read_item, sizeof(item)) == 0);

    /* Remove the item */
    status = psa_ps_remove(uid);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* Expect it to have gone */
    status = psa_ps_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);
}

/**
 * Creates a new slot and if supported, uses the psa_ps_set_extended()
 * method to set the object value in chunks.
 */
void ps_api_tests::createAndSetExtended()
{
    psa_status_t status;
    psa_storage_uid_t uid = 0xffff1;
    struct psa_storage_info_t storage_info;
    static const size_t ITEM_SIZE = 100;
    uint8_t item[ITEM_SIZE];
    uint8_t read_item[ITEM_SIZE];

    if ((psa_ps_get_support() & PSA_STORAGE_SUPPORT_SET_EXTENDED) == 0)
        return;

    memset(item, 0xaa, sizeof(item));

    /* Probe to check item does not exist */
    status = psa_ps_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);

    /* Create empty store record with capcity for the item */
    status = psa_ps_create(uid, sizeof(item), PSA_STORAGE_FLAG_NONE);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* The psa_ps_set_extended() method is optional so respect
     * the feature capabilities advertised.
     */
    uint32_t supported_features = psa_ps_get_support();

    if (supported_features & PSA_STORAGE_SUPPORT_SET_EXTENDED) {

        size_t offset = 0;
        size_t chunk_len = 10;

        while (offset + chunk_len <= ITEM_SIZE) {

            status = psa_ps_set_extended(uid, offset, chunk_len, &item[offset]);
            CHECK_EQUAL(PSA_SUCCESS, status);

            offset += chunk_len;
        }

        /* Expect the item to have been saved in its entirety  */
        size_t read_len = 0;
        status = psa_ps_get(uid, 0, sizeof(read_item), read_item, &read_len);
        CHECK_EQUAL(PSA_SUCCESS, status);
        CHECK_EQUAL(sizeof(item), read_len);
        CHECK(memcmp(item, read_item, sizeof(item)) == 0);
    }

    /* Remove the item */
    status = psa_ps_remove(uid);
    CHECK_EQUAL(PSA_SUCCESS, status);

    /* Expect it to have gone */
    status = psa_ps_get_info(uid, &storage_info);
    CHECK_EQUAL(PSA_ERROR_DOES_NOT_EXIST, status);
}