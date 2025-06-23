/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <psa/crypto.h>
#include "psa_crypto_client.h"
#include "crypto_caller_selector.h"


psa_status_t psa_asymmetric_decrypt(psa_key_id_t id, psa_algorithm_t alg,
	const uint8_t *input, size_t input_length,
	const uint8_t *salt, size_t salt_length,
	uint8_t *output, size_t output_size, size_t *output_length)
{
	if (psa_crypto_client_instance.init_status != PSA_SUCCESS)
		return psa_crypto_client_instance.init_status;

	return crypto_caller_asymmetric_decrypt(&psa_crypto_client_instance.base,
		id, alg,
		input, input_length,
		salt, salt_length,
		output, output_size, output_length);
}
