/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CRYPTO_PROVIDER_SERIALIZER_H
#define PACKEDC_CRYPTO_PROVIDER_SERIALIZER_H

#include <service/crypto/provider/serializer/crypto_provider_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the crypto service provider.
 */
const struct crypto_provider_serializer *packedc_crypto_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_CRYPTO_PROVIDER_SERIALIZER_H */
