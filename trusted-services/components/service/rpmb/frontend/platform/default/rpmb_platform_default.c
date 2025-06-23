/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpmb_platform_default.h"
#include "psa/crypto.h"

static psa_status_t rpmb_platform_derive_key(void *context, const uint8_t *data,
					     size_t data_length, uint8_t *key, size_t key_length)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	size_t hash_length = 0;
	const uint8_t dummy_huk[] = {
		0x32, 0x2b, 0x78, 0x27, 0xa3, 0x08, 0xcb, 0x5e,
		0xb4, 0x12, 0x0b, 0xab, 0x96, 0xd4, 0x3d, 0x4e,
		0x7b, 0xc4, 0x46, 0x46, 0xad, 0x93, 0xe9, 0x03,
		0x28, 0x47, 0xe8, 0xb6, 0x2c, 0xec, 0x5f, 0x14
	};

	(void)context;

	status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	if (status != PSA_SUCCESS)
		return status;

	status = psa_hash_update(&operation, dummy_huk, sizeof(dummy_huk));
	if (status != PSA_SUCCESS)
		return status;

	status = psa_hash_update(&operation, data, data_length);
	if (status != PSA_SUCCESS)
		return status;

	status = psa_hash_finish(&operation, key, key_length, &hash_length);
	if (status != PSA_SUCCESS)
		return status;

	if (hash_length != key_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	return PSA_SUCCESS;
}

static psa_status_t rpmb_platform_get_nonce(void *context, uint8_t *nonce, size_t nonce_length)
{
	(void)context;

	return psa_generate_random(nonce, nonce_length);
}

static psa_status_t rpmb_platform_calculate_mac(void *context, const uint8_t *key,
						size_t key_length,
						const struct rpmb_data_frame *frames,
						size_t frame_count, uint8_t *mac, size_t mac_length)
{
	/* Length of the data frame from the start of the data field to the end of the frame */
	const size_t frame_hash_length =
		sizeof(struct rpmb_data_frame) - offsetof(struct rpmb_data_frame, data);
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	size_t hash_length = 0;
	size_t i = 0;

	(void)context;

	status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	if (status != PSA_SUCCESS)
		return status;

	status = psa_hash_update(&operation, key, key_length);
	if (status != PSA_SUCCESS)
		return status;

	for (i = 0; i < frame_count; i++) {
		/* Hash data, nonce, write counter, address, block, result, req/resp fields */
		status = psa_hash_update(&operation, (const uint8_t *)frames[i].data,
					 frame_hash_length);
		if (status != PSA_SUCCESS)
			return status;
	}

	status = psa_hash_finish(&operation, mac, mac_length, &hash_length);
	if (status != PSA_SUCCESS)
		return status;

	if (hash_length != mac_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	return PSA_SUCCESS;
}

struct rpmb_platform *rpmb_platform_default_init(struct rpmb_platform_default *context)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	static struct rpmb_platform_interface interface = {
		rpmb_platform_derive_key,
		rpmb_platform_get_nonce,
		rpmb_platform_calculate_mac
	};

	if (!context)
		return NULL;

	status = psa_crypto_init();
	if (status != PSA_SUCCESS)
		return NULL;

	context->platform.context = context;
	context->platform.interface = &interface;

	return &context->platform;
}

void rpmc_platform_default_deinit(struct rpmb_platform_default *context)
{
	*context = (struct rpmb_platform_default) { 0 };
}
