/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STUB_CRYPTO_CALLER_GENERATE_RANDOM_H
#define STUB_CRYPTO_CALLER_GENERATE_RANDOM_H

#include <psa/crypto.h>
#include <service/common/client/service_client.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline psa_status_t crypto_caller_generate_random(struct service_client *context,
	uint8_t *output, size_t output_size)
{
	(void)context;
	(void)output;
	(void)output_size;

	return PSA_ERROR_NOT_SUPPORTED;
}

#ifdef __cplusplus
}
#endif

#endif /* STUB_CRYPTO_CALLER_GENERATE_RANDOM_H */
