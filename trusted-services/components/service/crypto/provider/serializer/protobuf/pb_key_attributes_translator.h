/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PB_CRYPTO_PROVIDER_KEY_ATTRIBUTES_TRANSLATOR_H
#define PB_CRYPTO_PROVIDER_KEY_ATTRIBUTES_TRANSLATOR_H

#include <service/crypto/protobuf/key_attributes.pb.h>
#include <service/crypto/backend/crypto_backend.h>

void pb_crypto_provider_translate_key_attributes(
    psa_key_attributes_t *psa_attributes,
    const ts_crypto_KeyAttributes *proto_attributes);

#endif /* PB_CRYPTO_PROVIDER_KEY_ATTRIBUTES_TRANSLATOR_H */
