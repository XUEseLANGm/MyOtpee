/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CRYPTO_CALLER_VERIFY_PKCS7_SIGNATURE_H
#define PACKEDC_CRYPTO_CALLER_VERIFY_PKCS7_SIGNATURE_H

#include <common/tlv/tlv.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/crypto/packed-c/opcodes.h>
#include <protocols/service/crypto/packed-c/verify_pkcs7_signature.h>
#include <service/common/client/service_client.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int crypto_caller_verify_pkcs7_signature(struct service_client *context,
						       const uint8_t *signature_cert,
						       uint64_t signature_cert_len,
						       const uint8_t *hash, uint64_t hash_len,
						       const uint8_t *public_key_cert,
						       uint64_t public_key_cert_len)
{
	int status = RPC_ERROR_INTERNAL;
	size_t req_len = 0;

	if (signature_cert_len > UINT16_MAX ||
		hash_len > UINT16_MAX ||
		public_key_cert_len > signature_cert_len)
		return RPC_ERROR_INVALID_VALUE;

	struct tlv_record signature_record = {
		.tag = TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_IN_TAG_SIGNATURE,
		.length = (uint16_t)signature_cert_len,
		.value = signature_cert
	};

	struct tlv_record hash_record = { .tag = TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_IN_TAG_HASH,
					  .length = (uint16_t)hash_len,
					  .value = hash };

	struct tlv_record public_key_record = {
		.tag = TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_IN_TAG_PUBLIC_KEY_CERT,
		.length = (uint16_t)public_key_cert_len,
		.value = public_key_cert
	};

	req_len += tlv_required_space(signature_record.length);
	req_len += tlv_required_space(hash_record.length);
	req_len += tlv_required_space(public_key_record.length);

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_session_begin(context->session, &req_buf, req_len, 0);

	if (call_handle) {
		uint8_t *resp_buf;
		size_t resp_len;
		service_status_t service_status;
		struct tlv_iterator req_iter;

		tlv_iterator_begin(&req_iter, req_buf, req_len);
		tlv_encode(&req_iter, &signature_record);
		tlv_encode(&req_iter, &hash_record);
		tlv_encode(&req_iter, &public_key_record);

		context->rpc_status = rpc_caller_session_invoke(
			call_handle, TS_CRYPTO_OPCODE_VERIFY_PKCS7_SIGNATURE, &resp_buf, &resp_len,
			&service_status);

		if (context->rpc_status == RPC_SUCCESS)
			status = service_status;

		rpc_caller_session_end(call_handle);
	}

	return status;
}

#ifdef __cplusplus
}
#endif

#endif /* PACKEDC_CRYPTO_CALLER_VERIFY_PKCS7_SIGNATURE_H */
