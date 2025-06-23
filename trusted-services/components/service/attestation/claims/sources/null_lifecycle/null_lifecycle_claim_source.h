/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NULL_LIFECYCLE_CLAIM_SOURCE_H
#define NULL_LIFECYCLE_CLAIM_SOURCE_H

#include <service/attestation/claims/claim_source.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Use this claim source in deployments where there is no hardware
 * backed support for a device's lifecycle state.  This claim
 * source just returns a lifecycle state of 'unknown'.
 */
struct null_lifecycle_claim_source
{
    struct claim_source base;
};

/**
 * \brief Initializes a struct null_lifecycle_claim_source
 *
 * \param[in] instance      The instance to initialze
 *
 * \return The initialize base claim_source structure
 */
struct claim_source *null_lifecycle_claim_source_init(
    struct null_lifecycle_claim_source *instance);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NULL_LIFECYCLE_CLAIM_SOURCE_H */
