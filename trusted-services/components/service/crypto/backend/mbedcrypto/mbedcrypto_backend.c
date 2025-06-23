/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/crypto/backend/mbedcrypto/mbedtls_psa_crypto_backend.h>
#include <service/crypto/backend/mbedcrypto/trng_adapter/trng_adapter.h>
#include <service/secure_storage/frontend/psa/its/its_frontend.h>

psa_status_t mbedcrypto_backend_init(struct storage_backend *storage_backend,
						int trng_instance_num)
{
	psa_status_t status;

	status = trng_adapter_init(trng_instance_num);

	if (status == PSA_SUCCESS)
		status = psa_its_frontend_init(storage_backend);

	if (status == PSA_SUCCESS)
		status = psa_crypto_init();

	return status;
}

void mbedcrypto_backend_deinit(void)
{
	trng_adapter_deinit();
}
