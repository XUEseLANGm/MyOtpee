/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PRELOADED_CLAIM_SOURCE_H
#define PRELOADED_CLAIM_SOURCE_H

#include <service/attestation/claims/claim.h>
#include <service/attestation/claims/claim_source.h>
#include <service/attestation/claims/claim_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A claim source that sources claims that have been preloaded
 * into a claim_vector.
 */
struct preloaded_claim_source
{
    struct claim_source base;

    const struct claim_vector *preloaded_claims;
};

/**
 * \brief Initializes a preloaded_claim_source.
 *
 * \param[in] instance      The preloaded_claim_source instance to initialze
 * \param[in] claims        claim_vector containing preloaded claims.
 *
 * \return The initialize base claim_source structure
 */
struct claim_source *preloaded_claim_source_init(struct preloaded_claim_source *instance,
                                const struct claim_vector *claims);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PRELOADED_CLAIM_SOURCE_H */
