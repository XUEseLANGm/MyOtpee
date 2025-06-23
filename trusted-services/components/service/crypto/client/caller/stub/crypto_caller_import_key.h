/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STUB_CRYPTO_CALLER_IMPORT_KEY_H
#define STUB_CRYPTO_CALLER_IMPORT_KEY_H

#include <psa/crypto.h>
#include <service/common/client/service_client.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline psa_status_t crypto_caller_import_key(struct service_client *context,
	const psa_key_attributes_t *attributes,
	const uint8_t *data, size_t data_length,
	psa_key_id_t *id)
{
	(void)context;
	(void)attributes;
	(void)data;
	(void)data_length;
	(void)id;

	return PSA_ERROR_NOT_SUPPORTED;
}

#ifdef __cplusplus
}
#endif

#endif /* STUB_CRYPTO_CALLER_IMPORT_KEY_H */
