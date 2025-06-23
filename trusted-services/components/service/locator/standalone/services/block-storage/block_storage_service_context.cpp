/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <cstring>
#include "psa/crypto.h"
#include "service/block_storage/provider/serializer/packed-c/packedc_block_storage_serializer.h"
#include "service/block_storage/factory/rpmb/block_store_factory.h"
#include "service/crypto/client/psa/psa_crypto_client.h"
#include "service/locator/interface/service_locator.h"
#include "block_storage_service_context.h"

block_storage_service_context::block_storage_service_context(const char *sn) :
	standalone_service_context(sn),
	m_block_storage_provider(),
	m_block_store(NULL),
	m_crypto_service_context(NULL),
	m_crypto_session(NULL)
{

}

block_storage_service_context::~block_storage_service_context()
{

}

void block_storage_service_context::do_init()
{
	/* The crypto service is used for key derivation in RPMB frontend */
	open_crypto_session();

	/* Create backend block store */
	m_block_store = rpmb_block_store_factory_create();
	assert(m_block_store);

	/* Initialise the block storage service provider */
	struct rpc_service_interface *rpc_iface = block_storage_provider_init(
		&m_block_storage_provider,
		m_block_store);
	assert(rpc_iface);

	block_storage_provider_register_serializer(&m_block_storage_provider,
						   packedc_block_storage_serializer_instance());

	standalone_service_context::set_rpc_interface(rpc_iface);
}

void block_storage_service_context::do_deinit()
{
	block_storage_provider_deinit(&m_block_storage_provider);
	rpmb_block_store_factory_destroy(m_block_store);
	close_crypto_session();
}

void block_storage_service_context::open_crypto_session()
{
	m_crypto_service_context = service_locator_query("sn:trustedfirmware.org:crypto:0");
	if (m_crypto_service_context) {
		m_crypto_session = service_context_open(m_crypto_service_context);
		if (m_crypto_session) {
			psa_crypto_client_init(m_crypto_session);
			psa_crypto_init();
		}
	}
}

void block_storage_service_context::close_crypto_session()
{
	psa_crypto_client_deinit();

	if (m_crypto_service_context && m_crypto_session) {
		service_context_close(m_crypto_service_context, m_crypto_session);
		m_crypto_session = NULL;

		service_context_relinquish(m_crypto_service_context);
		m_crypto_service_context = NULL;
	}
}
