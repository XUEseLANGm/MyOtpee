/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <psa/crypto.h>
#include "psa_crypto_client.h"
#include "crypto_caller_selector.h"

psa_status_t psa_sign_message(
	psa_key_id_t id,
	psa_algorithm_t alg,
	const uint8_t *input,
	size_t input_length,
	uint8_t *signature,
	size_t signature_size,
	size_t *signature_length)
{
	if (psa_crypto_client_instance.init_status != PSA_SUCCESS)
		return psa_crypto_client_instance.init_status;

	return crypto_caller_sign_message(&psa_crypto_client_instance.base,
		id, alg,
		input, input_length,
		signature, signature_size, signature_length);
}
