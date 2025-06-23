/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <psa/crypto.h>
#include <service/crypto/client/psa/psa_crypto_client.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <rpc/dummy/dummy_caller.h>
#include "stub_crypto_backend.h"

psa_status_t stub_crypto_backend_init(void)
{
	static struct rpc_caller_interface dummy_caller;
	struct rpc_caller_session session = { 0 };
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;

	rpc_status = dummy_caller_init(&dummy_caller, RPC_SUCCESS, PSA_ERROR_SERVICE_FAILURE);
	if (rpc_status != RPC_SUCCESS)
		return PSA_ERROR_GENERIC_ERROR;

	rpc_status = rpc_caller_session_find_and_open(&session, &dummy_caller, NULL, 0);
	if (rpc_status != RPC_SUCCESS)
		return PSA_ERROR_GENERIC_ERROR;

	status = psa_crypto_client_init(&session);

	if (status == PSA_SUCCESS)
		status = psa_crypto_init();

	return status;
}

void stub_crypto_backend_deinit(void)
{
	psa_crypto_client_deinit();
}
