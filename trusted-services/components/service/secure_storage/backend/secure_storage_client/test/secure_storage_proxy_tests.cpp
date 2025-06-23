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


TEST_GROUP(SecureStorageProxyTests)
{
    /* Runs ITS and PS API tests against a service provider, accessed via a
     * proxy.  The frontend/backend chain looks like this:
     * its/ps_frontend->secure_storage_client->secure_storage_provider->secure_storage_client
     * ->secure_storage_provider->mock_store
     */
    void setup()
    {
        struct rpc_uuid service_uuid = { .uuid = TS_PSA_PROTECTED_STORAGE_UUID };
        /* Initialise the actual storage provider */
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

        /* Initialise the intermediate proxy */
        struct storage_backend *proxy_backend =
            secure_storage_client_init(&m_proxy_client, &m_storage_session);
        struct rpc_service_interface *proxy_ep =
            secure_storage_provider_init(&m_proxy_provider, proxy_backend, &service_uuid);
        direct_caller_init(&m_proxy_caller, proxy_ep);

        rpc_caller_session_find_and_open(&m_proxy_session, &m_proxy_caller, &service_uuid,
                                         4096);

        /* Initialise the client-side backend that talks to the proxy */
        struct storage_backend *storage_client_backend =
            secure_storage_client_init(&m_storage_client, &m_proxy_session);

        psa_its_frontend_init(storage_client_backend);
        psa_ps_frontend_init(storage_client_backend);
    }

    void teardown()
    {
        mock_store_deinit(&m_mock_store);
        secure_storage_provider_deinit(&m_storage_provider);

        secure_storage_client_deinit(&m_proxy_client);
        secure_storage_provider_deinit(&m_proxy_provider);

        secure_storage_client_deinit(&m_storage_client);

        rpc_caller_session_close(&m_proxy_session);
        rpc_caller_session_close(&m_storage_session);

        direct_caller_deinit(&m_proxy_caller);
        direct_caller_deinit(&m_storage_caller);
    }

    struct mock_store m_mock_store;
    struct secure_storage_provider m_storage_provider;
    struct secure_storage_client m_proxy_client;
    struct secure_storage_provider m_proxy_provider;
    struct secure_storage_client m_storage_client;
    struct rpc_caller_interface m_storage_caller;
    struct rpc_caller_interface m_proxy_caller;
    struct rpc_caller_session m_storage_session;
    struct rpc_caller_session m_proxy_session;
};

TEST(SecureStorageProxyTests, itsStoreNewItem)
{
    its_api_tests::storeNewItem();
}

TEST(SecureStorageProxyTests, itsStorageLimitTest)
{
    its_api_tests::storageLimitTest(MOCK_STORE_ITEM_SIZE_LIMIT);
}

TEST(SecureStorageProxyTests, psSet)
{
    ps_api_tests::set();
}

TEST(SecureStorageProxyTests, psCreateAndSetExtended)
{
    ps_api_tests::createAndSetExtended();
}
