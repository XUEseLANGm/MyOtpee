/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <psa/crypto.h>
#include <service/attestation/claims/claim.h>
#include "boot_seed_generator.h"

static bool boot_seed_generator_get_claim(void *context, struct claim *claim);


struct claim_source *boot_seed_generator_init(struct boot_seed_generator *instance)
{
    instance->base.get_claim = boot_seed_generator_get_claim;
    instance->base.context = instance;

    instance->is_generated = false;

    return &instance->base;
}

static bool boot_seed_generator_get_claim(void *context, struct claim *claim)
{
    struct boot_seed_generator *instance = (struct boot_seed_generator*)context;

    /* Generate if no seed has been generated yet */
    if (!instance->is_generated) {

        psa_status_t status;
        status = psa_generate_random(instance->boot_seed, sizeof(instance->boot_seed));
        instance->is_generated = (status == PSA_SUCCESS);
    }

    if (instance->is_generated) {

        claim->category = CLAIM_CATEGORY_DEVICE;
        claim->subject_id = CLAIM_SUBJECT_ID_BOOT_SEED;
        claim->variant_id = CLAIM_VARIANT_ID_BYTE_STRING;
        claim->raw_data = NULL;

        claim->variant.byte_string.bytes = instance->boot_seed;
        claim->variant.byte_string.len = sizeof(instance->boot_seed);
    }

    return instance->is_generated;
}
