/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "smm_variable_service_context.h"
#include <protocols/rpc/common/packed-c/encoding.h>
#include <service/crypto/client/psa/psa_crypto_client.h>
#include <psa/crypto.h>

smm_variable_service_context::smm_variable_service_context(const char *sn) :
	standalone_service_context(sn, RPC_BUFFER_SIZE),
	m_smm_variable_provider(),
	m_persistent_store_client(),
	m_volatile_store(),
	m_storage_service_context(NULL),
	m_crypto_service_context(NULL),
	m_storage_session(NULL),
	m_crypto_session(NULL)
{

}

smm_variable_service_context::~smm_variable_service_context()
{

}

void smm_variable_service_context::do_init()
{
	/* Initialize crypto backend session */
	m_crypto_service_context = service_locator_query("sn:trustedfirmware.org:crypto:0");
	if (m_crypto_service_context) {
		m_crypto_session = service_context_open(m_crypto_service_context);
		if (m_crypto_session) {
			psa_crypto_client_init(m_crypto_session);
			psa_crypto_init();
		}
	}

	/* Initialize the persistent storage backend - uses protected storage service */
	struct storage_backend *peristent_backend = NULL;

	/* Locate and open RPC session with the protected-storage service */
	m_storage_service_context =
		service_locator_query("sn:trustedfirmware.org:protected-storage:0");

	if (m_storage_service_context) {

		m_storage_session = service_context_open(m_storage_service_context);

		if (m_storage_session) {

			peristent_backend = secure_storage_client_init(
				&m_persistent_store_client, m_storage_session);
		}
	}

	/* Initialize the volatile storage backend */
	struct storage_backend *volatile_backend  = mock_store_init(&m_volatile_store);

	/* Initialize the smm_variable service provider */
	struct rpc_service_interface *service_iface = smm_variable_provider_init(
		&m_smm_variable_provider,
 		0,		/* owner id */
		MAX_VARIABLES,
		peristent_backend,
		volatile_backend);

	standalone_service_context::set_rpc_interface(service_iface);
}

void smm_variable_service_context::do_deinit()
{
	if (m_storage_session) {
		service_context_close(m_storage_service_context, m_storage_session);
		m_storage_session = NULL;
	}

	if (m_storage_service_context) {
		service_context_relinquish(m_storage_service_context);
		m_storage_service_context = NULL;
	}

	smm_variable_provider_deinit(&m_smm_variable_provider);
	secure_storage_client_deinit(&m_persistent_store_client);
	mock_store_deinit(&m_volatile_store);

	psa_crypto_client_deinit();

	if (m_crypto_service_context && m_crypto_session) {
		service_context_close(m_crypto_service_context, m_crypto_session);
		m_crypto_session = NULL;

		service_context_relinquish(m_crypto_service_context);
		m_crypto_service_context = NULL;
	}
}
