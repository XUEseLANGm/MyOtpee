/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <psa/crypto.h>
#include "psa_crypto_client.h"
#include "crypto_caller_selector.h"


psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
	const uint8_t *data, size_t data_length, psa_key_id_t *id)
{
	if (psa_crypto_client_instance.init_status != PSA_SUCCESS)
		return psa_crypto_client_instance.init_status;

	return crypto_caller_import_key(&psa_crypto_client_instance.base,
		attributes,
		data, data_length, id);
}
