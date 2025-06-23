/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CRYPTO_CALLER_KEY_ATTRIBUTES_H
#define PACKEDC_CRYPTO_CALLER_KEY_ATTRIBUTES_H

#include <psa/crypto.h>
#include <protocols/service/crypto/packed-c/key_attributes.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void packedc_crypto_caller_translate_key_attributes_to_proto(
	struct ts_crypto_key_attributes *proto_attributes,
	const psa_key_attributes_t *psa_attributes)
{
	proto_attributes->type = psa_get_key_type(psa_attributes);
	proto_attributes->key_bits = psa_get_key_bits(psa_attributes);
	proto_attributes->lifetime = psa_get_key_lifetime(psa_attributes);
	proto_attributes->id = psa_get_key_id(psa_attributes);

	proto_attributes->policy.usage = psa_get_key_usage_flags(psa_attributes);
	proto_attributes->policy.alg = psa_get_key_algorithm(psa_attributes);
 }

static inline void packedc_crypto_caller_translate_key_attributes_from_proto(
	psa_key_attributes_t *psa_attributes,
	const struct ts_crypto_key_attributes *proto_attributes)
{
	psa_set_key_type(psa_attributes, proto_attributes->type);
	psa_set_key_bits(psa_attributes, proto_attributes->key_bits);
	psa_set_key_lifetime(psa_attributes, proto_attributes->lifetime);

	if (proto_attributes->lifetime == PSA_KEY_LIFETIME_PERSISTENT) {

		psa_set_key_id(psa_attributes, proto_attributes->id);
	}

	psa_set_key_usage_flags(psa_attributes, proto_attributes->policy.usage);
	psa_set_key_algorithm(psa_attributes, proto_attributes->policy.alg);
}

#ifdef __cplusplus
}
#endif

#endif /* PACKEDC_CRYPTO_CALLER_KEY_ATTRIBUTES_H */
