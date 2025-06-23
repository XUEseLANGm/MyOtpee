/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef METADATA_SERIALIZER_V1_H
#define METADATA_SERIALIZER_V1_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct metadata_serializer;

/**
 * \brief Return a metadata_serializer for version 1 serialization
 *
 */
const struct metadata_serializer *metadata_serializer_v1(void);

#ifdef __cplusplus
}
#endif

#endif /* METADATA_SERIALIZER_V1_H */
