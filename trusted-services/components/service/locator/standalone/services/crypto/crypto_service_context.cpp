/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "crypto_service_context.h"
#include <service/crypto/factory/crypto_provider_factory.h>
#include <service/crypto/backend/mbedcrypto/mbedcrypto_backend.h>

crypto_service_context::crypto_service_context(const char *sn, unsigned int encoding) :
    standalone_service_context(sn),
    m_encoding(encoding),
    m_crypto_provider(NULL),
    m_storage_client(),
    m_null_store(),
    m_storage_service_context(NULL),
    m_storage_session(NULL)
{

}

crypto_service_context::~crypto_service_context()
{

}

void crypto_service_context::do_init()
{
    struct storage_backend *storage_backend = NULL;
    struct storage_backend *null_storage_backend = null_store_init(&m_null_store);

    /* Locate and open RPC session with internal-trusted-storage service to
     * provide a persistent keystore
     */
    m_storage_service_context =
        service_locator_query("sn:trustedfirmware.org:internal-trusted-storage:0");

    if (m_storage_service_context) {

        m_storage_session =
            service_context_open(m_storage_service_context);

        if (m_storage_session) {

            storage_backend = secure_storage_client_init(&m_storage_client, m_storage_session);
        }
    }

    if (!storage_backend) {

        /* Something has gone wrong with establishing a session with the
         * storage service endpoint
         */
        storage_backend = null_storage_backend;
    }

    /* Initialise the crypto service provider */
    struct rpc_service_interface *crypto_iface = NULL;

    if (mbedcrypto_backend_init(storage_backend, 0) == PSA_SUCCESS) {

        if (m_encoding == TS_RPC_ENCODING_PACKED_C)
            m_crypto_provider = crypto_provider_factory_create();
        else
            m_crypto_provider = crypto_protobuf_provider_factory_create();

        crypto_iface = service_provider_get_rpc_interface(&m_crypto_provider->base_provider);
    }

    standalone_service_context::set_rpc_interface(crypto_iface);
}

void crypto_service_context::do_deinit()
{
    if (m_storage_session) {
        service_context_close(m_storage_service_context, m_storage_session);
        m_storage_session = NULL;
    }

    if (m_storage_service_context) {
        service_context_relinquish(m_storage_service_context);
        m_storage_service_context = NULL;
    }

    crypto_provider_factory_destroy(m_crypto_provider);
    secure_storage_client_deinit(&m_storage_client);
    null_store_deinit(&m_null_store);
}
