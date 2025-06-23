/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_BLOCK_STORAGE_SERVICE_CONTEXT_H
#define STANDALONE_BLOCK_STORAGE_SERVICE_CONTEXT_H

#include <service/locator/standalone/standalone_service_context.h>
#include <rpc/direct/direct_caller.h>
#include <service/block_storage/provider/block_storage_provider.h>
#include <service/block_storage/block_store/block_store.h>

class block_storage_service_context : public standalone_service_context
{
public:
	block_storage_service_context(const char *sn);
	virtual ~block_storage_service_context();

private:

	void do_init();
	void do_deinit();

	void open_crypto_session();
	void close_crypto_session();

	struct block_storage_provider m_block_storage_provider;
	struct block_store *m_block_store;
	struct service_context *m_crypto_service_context;
	struct rpc_caller_session *m_crypto_session;
};

#endif /* STANDALONE_BLOCK_STORAGE_SERVICE_CONTEXT_H */
