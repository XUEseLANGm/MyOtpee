/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_IPC_CRYPTO_CALLER_VERIFY_PKCS7_SIGNATURE_H
#define PSA_IPC_CRYPTO_CALLER_VERIFY_PKCS7_SIGNATURE_H

#include <rpc/common/interface/rpc_status.h>
#include <service/common/client/service_client.h>

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
	(void)context;
	(void)signature_cert;
	(void)signature_cert_len;
	(void)hash;
	(void)hash_len;
	(void)public_key_cert;
	(void)public_key_cert_len;

	return RPC_ERROR_INTERNAL;
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_IPC_CRYPTO_CALLER_VERIFY_PKCS7_SIGNATURE_H */
