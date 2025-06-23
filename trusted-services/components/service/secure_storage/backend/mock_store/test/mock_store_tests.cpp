/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <service/secure_storage/frontend/psa/its/its_frontend.h>
#include <service/secure_storage/frontend/psa/its/test/its_api_tests.h>
#include <service/secure_storage/frontend/psa/ps/ps_frontend.h>
#include <service/secure_storage/frontend/psa/ps/test/ps_api_tests.h>
#include <service/secure_storage/backend/mock_store/mock_store.h>


TEST_GROUP(MockStoreTests)
{
    void setup()
    {
        struct storage_backend *storage_backend = mock_store_init(&m_mock_store);

        psa_its_frontend_init(storage_backend);
        psa_ps_frontend_init(storage_backend);
    }

    void teardown()
    {
        mock_store_deinit(&m_mock_store);
    }

    struct mock_store m_mock_store;
};

TEST(MockStoreTests, itsStoreNewItem)
{
    its_api_tests::storeNewItem();
}

TEST(MockStoreTests, itsStorageLimitTest)
{
    its_api_tests::storageLimitTest(MOCK_STORE_ITEM_SIZE_LIMIT);
}

TEST(MockStoreTests, psSet)
{
    ps_api_tests::set();
}

TEST(MockStoreTests, psCreateAndSetExtended)
{
    ps_api_tests::createAndSetExtended();
}
