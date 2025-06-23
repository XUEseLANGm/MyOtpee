/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <psa/crypto.h>
#include <service/crypto/client/psa/psa_crypto_client.h>
#include <protocols/rpc/common/packed-c/status.h>
#include "crypto_ipc_backend.h"

psa_status_t crypto_ipc_backend_init(struct rpc_caller_session *session)
{
	psa_status_t status = psa_crypto_client_init(session);

	if (status == PSA_SUCCESS)
		status = psa_crypto_init();

	return status;
}

void crypto_ipc_backend_deinit(void)
{
	psa_crypto_client_deinit();
}
