/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_AEAD_PROVIDER_SERIALIZER_H
#define PACKEDC_AEAD_PROVIDER_SERIALIZER_H

#include <service/crypto/provider/extension/aead/serializer/aead_provider_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the aead service provider.
 */
const struct aead_provider_serializer *packedc_aead_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_AEAD_PROVIDER_SERIALIZER_H */
