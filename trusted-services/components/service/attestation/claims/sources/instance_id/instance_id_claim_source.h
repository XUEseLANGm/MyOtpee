/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef INSTANCE_ID_CLAIM_SOURCE_H
#define INSTANCE_ID_CLAIM_SOURCE_H

#include <stdbool.h>
#include <stdint.h>
#include <psa/crypto.h>
#include <service/attestation/claims/claim_source.h>

/* Instance ID defines */
#define INSTANCE_ID_HASH_ALG        PSA_ALG_SHA_256
#define INSTANCE_ID_HASH_LEN        PSA_HASH_LENGTH(INSTANCE_ID_HASH_ALG)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A claim_source that provides an identifier for the device,
 * comprising a hash of the IAK public key.
 */
struct instance_id_claim_source
{
    struct claim_source base;

    bool is_known;

    /* Space for the hashed key + a single type byte (see EAT) */
    uint8_t instance_id[INSTANCE_ID_HASH_LEN + 1];
};

/**
 * \brief Initializes a struct instance_id_claim_source
 *
 * \param[in] instance      The instance to initialze
 *
 * \return The initialize base claim_source structure
 */
struct claim_source *instance_id_claim_source_init(struct instance_id_claim_source *instance);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* INSTANCE_ID_CLAIM_SOURCE_H */
