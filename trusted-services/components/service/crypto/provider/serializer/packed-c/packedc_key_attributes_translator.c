/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "packedc_key_attributes_translator.h"

void packedc_crypto_provider_translate_key_attributes_from_proto(
    psa_key_attributes_t *psa_attributes,
    const struct ts_crypto_key_attributes *proto_attributes)
{
    psa_set_key_type(psa_attributes, proto_attributes->type);
    psa_set_key_bits(psa_attributes, proto_attributes->key_bits);
    psa_set_key_lifetime(psa_attributes, proto_attributes->lifetime);

    if (proto_attributes->lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
        namespaced_key_id_t ns_key_id = NAMESPACED_KEY_ID_INIT;

        /* Note: that namespace is set later */
        namespaced_key_id_init(&ns_key_id, 0, proto_attributes->id);
        psa_set_key_id(psa_attributes, ns_key_id);
    }

    psa_set_key_usage_flags(psa_attributes, proto_attributes->policy.usage);
    psa_set_key_algorithm(psa_attributes, proto_attributes->policy.alg);
}

void packedc_crypto_provider_translate_key_attributes_to_proto(
    struct ts_crypto_key_attributes *proto_attributes,
    const psa_key_attributes_t *psa_attributes)
{
    namespaced_key_id_t ns_key_id = NAMESPACED_KEY_ID_INIT;

    proto_attributes->type = psa_get_key_type(psa_attributes);
    proto_attributes->key_bits = psa_get_key_bits(psa_attributes);
    proto_attributes->lifetime = psa_get_key_lifetime(psa_attributes);
    ns_key_id = psa_get_key_id(psa_attributes);
    proto_attributes->id = namespaced_key_id_get_key_id(ns_key_id);

    proto_attributes->policy.usage = psa_get_key_usage_flags(psa_attributes);
    proto_attributes->policy.alg = psa_get_key_algorithm(psa_attributes);
}
