/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "psa_crypto_client.h"
#include "crypto_caller_selector.h"

psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
	if (psa_crypto_client_instance.init_status != PSA_SUCCESS)
		return psa_crypto_client_instance.init_status;

	return crypto_caller_generate_random(&psa_crypto_client_instance.base,
		output, output_size);
}
