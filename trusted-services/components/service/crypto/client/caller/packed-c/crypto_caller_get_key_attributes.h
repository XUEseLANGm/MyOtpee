/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CRYPTO_CALLER_GET_KEY_ATTRIBUTES_H
#define PACKEDC_CRYPTO_CALLER_GET_KEY_ATTRIBUTES_H

#include <string.h>
#include <psa/crypto.h>
#include <service/common/client/service_client.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/crypto/packed-c/opcodes.h>
#include <protocols/service/crypto/packed-c/get_key_attributes.h>
#include "crypto_caller_key_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline psa_status_t crypto_caller_get_key_attributes(struct service_client *context,
	psa_key_id_t key,
	psa_key_attributes_t *attributes)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_get_key_attributes_in req_msg;
	size_t req_len = sizeof(struct ts_crypto_get_key_attributes_in);

	req_msg.id = key;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_session_begin(context->session, &req_buf, req_len,
					       sizeof(struct ts_crypto_get_key_attributes_out));

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		service_status_t service_status;

		memcpy(req_buf, &req_msg, req_len);

		context->rpc_status =
			rpc_caller_session_invoke(call_handle, TS_CRYPTO_OPCODE_GET_KEY_ATTRIBUTES,
						  &resp_buf, &resp_len, &service_status);

		if (context->rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_crypto_get_key_attributes_out)) {

					struct ts_crypto_get_key_attributes_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_crypto_get_key_attributes_out));
					packedc_crypto_caller_translate_key_attributes_from_proto(
						attributes, &resp_msg.attributes);
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

#ifdef __cplusplus
}
#endif

#endif /* PACKEDC_CRYPTO_CALLER_GET_KEY_ATTRIBUTES_H */
