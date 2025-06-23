/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef METADATA_SERIALIZER_V2_H
#define METADATA_SERIALIZER_V2_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct metadata_serializer;

/**
 * \brief Return a metadata_serializer for version 2 serialization
 *
 */
const struct metadata_serializer *metadata_serializer_v2(void);

#ifdef __cplusplus
}
#endif

#endif /* METADATA_SERIALIZER_V2_H */
