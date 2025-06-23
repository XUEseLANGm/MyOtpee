/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_ATTEST_PROVIDER_SERIALIZER_H
#define PACKEDC_ATTEST_PROVIDER_SERIALIZER_H

#include "components/service/attestation/provider/serializer/attest_provider_serializer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the attestation service provider.
 */
const struct attest_provider_serializer *packedc_attest_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_ATTEST_PROVIDER_SERIALIZER_H */
