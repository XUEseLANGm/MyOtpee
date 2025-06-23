/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_BLOCK_STORAGE_PROVIDER_SERIALIZER_H
#define PACKEDC_BLOCK_STORAGE_PROVIDER_SERIALIZER_H

#include <service/block_storage/provider/serializer/block_storage_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Singleton method to provide access to the packed-c serializer
 * for the block storage service provider.
 */
const struct block_storage_serializer *packedc_block_storage_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_BLOCK_STORAGE_PROVIDER_SERIALIZER_H */
