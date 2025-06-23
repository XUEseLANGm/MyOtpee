/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_MAC_PROVIDER_SERIALIZER_H
#define PACKEDC_MAC_PROVIDER_SERIALIZER_H

#include <service/crypto/provider/extension/mac/serializer/mac_provider_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the mac service provider.
 */
const struct mac_provider_serializer *packedc_mac_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_MAC_PROVIDER_SERIALIZER_H */
