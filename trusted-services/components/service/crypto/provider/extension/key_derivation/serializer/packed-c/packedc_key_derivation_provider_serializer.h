/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_KEY_DERIVATION_PROVIDER_SERIALIZER_H
#define PACKEDC_KEY_DERIVATION_PROVIDER_SERIALIZER_H

#include <service/crypto/provider/extension/key_derivation/serializer/key_derivation_provider_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the key_derivation service provider.
 */
const struct key_derivation_provider_serializer
    *packedc_key_derivation_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_KEY_DERIVATION_PROVIDER_SERIALIZER_H */
