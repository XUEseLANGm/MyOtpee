/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <rpc/direct/direct_caller.h>
#include "service/secure_storage/frontend/secure_storage_provider/secure_storage_uuid.h"
#include <service/secure_storage/frontend/psa/its/its_frontend.h>
#include <service/secure_storage/frontend/psa/its/test/its_api_tests.h>
#include <service/secure_storage/frontend/psa/ps/ps_frontend.h>
#include <service/secure_storage/frontend/psa/ps/test/ps_api_tests.h>
#include <service/secure_storage/frontend/secure_storage_provider/secure_storage_provider.h>
#include <service/secure_storage/backend/secure_storage_client/secure_storage_client.h>
#include <service/secure_storage/backend/mock_store/mock_store.h>


TEST_GROUP(SecureStorageClientTests)
{
    /* Runs ITS and PS API tests against a typical service configuration
     * comprising:
     * its/ps_frontend->secure_storage_client->secure_storage_provider->mock_store
     */
    void setup()
    {
        struct rpc_uuid service_uuid = { .uuid = TS_PSA_INTERNAL_TRUSTED_STORAGE_UUID };
        struct storage_backend *storage_provider_backend =
            mock_store_init(&m_mock_store);
        struct rpc_service_interface *storage_ep =
            secure_storage_provider_init(&m_storage_provider, storage_provider_backend,
                                         &service_uuid);
        rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

        rpc_status = direct_caller_init(&m_storage_caller, storage_ep);
        CHECK_EQUAL(RPC_SUCCESS, rpc_status);

        rpc_status = rpc_caller_session_find_and_open(&m_storage_session, &m_storage_caller,
                                                      &service_uuid, 4096);
        CHECK_EQUAL(RPC_SUCCESS, rpc_status);

        struct storage_backend *storage_client_backend =
            secure_storage_client_init(&m_storage_client, &m_storage_session);

        psa_its_frontend_init(storage_client_backend);
        psa_ps_frontend_init(storage_client_backend);
    }

    void teardown()
    {
        mock_store_deinit(&m_mock_store);
        secure_storage_provider_deinit(&m_storage_provider);
        secure_storage_client_deinit(&m_storage_client);
        rpc_caller_session_close(&m_storage_session);
        direct_caller_deinit(&m_storage_caller);
    }

    struct mock_store m_mock_store;
    struct secure_storage_provider m_storage_provider;
    struct secure_storage_client m_storage_client;
    struct rpc_caller_interface m_storage_caller;
    struct rpc_caller_session m_storage_session;
};

TEST(SecureStorageClientTests, itsStoreNewItem)
{
    its_api_tests::storeNewItem();
}

TEST(SecureStorageClientTests, itsStorageLimitTest)
{
    its_api_tests::storageLimitTest(MOCK_STORE_ITEM_SIZE_LIMIT);
}

TEST(SecureStorageClientTests, psSet)
{
    ps_api_tests::set();
}

TEST(SecureStorageClientTests, psCreateAndSetExtended)
{
    ps_api_tests::createAndSetExtended();
}
