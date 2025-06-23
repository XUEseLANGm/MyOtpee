/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <string.h>
#include "iat_client.h"
#include "rpc_caller_session.h"
#include <common/tlv/tlv.h>
#include <psa/initial_attestation.h>
#include <service/common/client/service_client.h>
#include <protocols/service/attestation/packed-c/get_token.h>
#include <protocols/service/attestation/packed-c/get_token_size.h>
#include <protocols/service/attestation/packed-c/opcodes.h>
#include <protocols/rpc/common/packed-c/status.h>

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

psa_status_t psa_initial_attest_get_token(
	const uint8_t *auth_challenge, size_t challenge_size,
	uint8_t *token_buf, size_t token_buf_size, size_t *token_size)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
	size_t req_len = tlv_required_space(challenge_size);
	struct tlv_record challenge_record = { 0 };
	rpc_call_handle call_handle;
	uint8_t *req_buf;

	if (!token_buf || !token_buf_size)
		return PSA_ERROR_INVALID_ARGUMENT;

	challenge_record.tag = TS_ATTESTATION_GET_TOKEN_IN_TAG_AUTH_CHALLENGE;
	challenge_record.length = challenge_size;
	challenge_record.value = auth_challenge;

	*token_size = 0;

	call_handle = rpc_caller_session_begin(instance.session, &req_buf, req_len,
					       tlv_required_space(token_buf_size));

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		service_status_t service_status;
		struct tlv_iterator req_iter;

		tlv_iterator_begin(&req_iter, req_buf, req_len);
		tlv_encode(&req_iter, &challenge_record);

		instance.rpc_status =
			rpc_caller_session_invoke(call_handle, TS_ATTESTATION_OPCODE_GET_TOKEN,
						  &resp_buf, &resp_len, &service_status);

		if (instance.rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {
				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;

				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
					TS_ATTESTATION_GET_TOKEN_OUT_TAG_TOKEN, &decoded_record)) {

					if (decoded_record.length <= token_buf_size) {

						memcpy(token_buf, decoded_record.value,
						       decoded_record.length);
						*token_size = decoded_record.length;
					} else {
						/* Provided buffer is too small */
						psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
					}
				} else {
					/* Mandatory response parameter missing */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_session_end(call_handle);
	}

	return psa_status;
}

psa_status_t psa_initial_attest_get_token_size(
	size_t challenge_size, size_t *token_size)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
	struct ts_attestation_get_token_size_in req_msg;
	size_t req_len = sizeof(struct ts_attestation_get_token_size_in);

	*token_size = 0;  /* For failure case */

	req_msg.challenge_size = challenge_size;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_session_begin(instance.session, &req_buf, req_len,
					       sizeof(struct ts_attestation_get_token_size_out));

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		service_status_t service_status;

		memcpy(req_buf, &req_msg, req_len);

		instance.rpc_status =
			rpc_caller_session_invoke(call_handle, TS_ATTESTATION_OPCODE_GET_TOKEN_SIZE,
						  &resp_buf, &resp_len, &service_status);

		if (instance.rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_attestation_get_token_size_out)) {

					struct ts_attestation_get_token_size_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_attestation_get_token_size_out));
					*token_size = resp_msg.token_size;
				}
				else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_session_end(call_handle);
	}

	return psa_status;
}
