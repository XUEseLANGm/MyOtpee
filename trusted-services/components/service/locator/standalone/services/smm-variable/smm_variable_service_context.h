/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_SMM_VARIABLE_SERVICE_CONTEXT_H
#define STANDALONE_SMM_VARIABLE_SERVICE_CONTEXT_H

#include <stddef.h>
#include <stdint.h>
#include <service/locator/standalone/standalone_service_context.h>
#include <service/uefi/smm_variable/provider/smm_variable_provider.h>
#include <service/secure_storage/backend/secure_storage_client/secure_storage_client.h>
#include <service/secure_storage/backend/mock_store/mock_store.h>

class smm_variable_service_context : public standalone_service_context
{
public:
	smm_variable_service_context(const char *sn);
	virtual ~smm_variable_service_context();

private:

	void do_init();
	void do_deinit();

	static const size_t MAX_VARIABLES = 40;

	/* Use an RPC buffer size that is typical for MM Communicate */
	static const size_t RPC_BUFFER_SIZE = 64 * 1024;

	struct smm_variable_provider m_smm_variable_provider;
	struct secure_storage_client m_persistent_store_client;
	struct mock_store m_volatile_store;
	struct service_context *m_storage_service_context;
	struct service_context *m_crypto_service_context;
	struct rpc_caller_session *m_storage_session;
	struct rpc_caller_session *m_crypto_session;
};

#endif /* STANDALONE_SMM_VARIABLE_SERVICE_CONTEXT_H */
