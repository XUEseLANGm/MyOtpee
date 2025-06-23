/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <string.h>

#include "../psa/iat_client.h"
#include <protocols/rpc/common/packed-c/status.h>
#include <psa/initial_attestation.h>
#include <psa/client.h>
#include <psa/sid.h>
#include <service/common/client/service_client.h>

/**
 * @brief      The singleton psa_iat_client instance
 *
 * The psa attestation C API assumes a single backend service provider.
 */
static struct service_client instance;


psa_status_t psa_iat_client_init(struct rpc_caller_session *session)
{
	return service_client_init(&instance, session);
}

void psa_iat_client_deinit(void)
{
	service_client_deinit(&instance);
}

int psa_iat_client_rpc_status(void)
{
	return instance.rpc_status;
}

psa_status_t psa_initial_attest_get_token(const uint8_t *auth_challenge,
					  size_t challenge_size,
					  uint8_t *token_buf,
					  size_t token_buf_size,
					  size_t *token_size)
{
	psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
	struct rpc_caller_interface *caller = instance.session->caller;
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_const_to_u32(auth_challenge), .len = challenge_size},
	};
	struct psa_outvec out_vec[] = {
		{ .base = psa_ptr_to_u32(token_buf), .len = token_buf_size},
	};

	if (!token_buf || !token_buf_size)
		return PSA_ERROR_INVALID_ARGUMENT;

	status = psa_call(caller, TFM_ATTESTATION_SERVICE_HANDLE,
			  TFM_ATTEST_GET_TOKEN, in_vec, IOVEC_LEN(in_vec),
			  out_vec, IOVEC_LEN(out_vec));
	if (status == PSA_SUCCESS) {
		*token_size = out_vec[0].len;
	}

	return status;
}

psa_status_t psa_initial_attest_get_token_size(size_t challenge_size,
						size_t *token_size)
{
	struct rpc_caller_interface *caller = instance.session->caller;
	psa_status_t status;
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&challenge_size), .len = sizeof(uint32_t)}
	};
	struct psa_outvec out_vec[] = {
		{ .base = psa_ptr_to_u32(token_size), .len = sizeof(uint32_t)}
	};

	status = psa_call(caller, TFM_ATTESTATION_SERVICE_HANDLE,
			  TFM_ATTEST_GET_TOKEN_SIZE,
			  in_vec, IOVEC_LEN(in_vec),
			  out_vec, IOVEC_LEN(out_vec));

	return status;
}
