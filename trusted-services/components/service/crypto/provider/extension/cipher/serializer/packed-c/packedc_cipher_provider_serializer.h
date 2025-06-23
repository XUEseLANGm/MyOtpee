/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CIPHER_PROVIDER_SERIALIZER_H
#define PACKEDC_CIPHER_PROVIDER_SERIALIZER_H

#include <service/crypto/provider/extension/cipher/serializer/cipher_provider_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the cipher service provider.
 */
const struct cipher_provider_serializer *packedc_cipher_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_CIPHER_PROVIDER_SERIALIZER_H */
