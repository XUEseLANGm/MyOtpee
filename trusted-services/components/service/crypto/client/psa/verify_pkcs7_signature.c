/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "crypto_caller_selector.h"
#include "crypto_client.h"
#include "psa_crypto_client.h"

int verify_pkcs7_signature(const uint8_t *signature_cert, uint64_t signature_cert_len,
			   const uint8_t *hash, uint64_t hash_len, const uint8_t *public_key_cert,
			   uint64_t public_key_cert_len)
{
	if (psa_crypto_client_instance.init_status != PSA_SUCCESS)
		return psa_crypto_client_instance.init_status;

	return crypto_caller_verify_pkcs7_signature(&psa_crypto_client_instance.base,
						    signature_cert, signature_cert_len, hash,
						    hash_len, public_key_cert, public_key_cert_len);
}
