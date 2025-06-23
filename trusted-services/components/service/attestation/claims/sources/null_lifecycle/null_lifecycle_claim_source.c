/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/attestation/claims/claim.h>
#include <psa/lifecycle.h>
#include "null_lifecycle_claim_source.h"

static bool null_lifecycle_claim_source_get_claim(void *context, struct claim *claim);


struct claim_source *null_lifecycle_claim_source_init(struct null_lifecycle_claim_source *instance)
{
    instance->base.get_claim = null_lifecycle_claim_source_get_claim;
    instance->base.context = instance;

    return &instance->base;
}

static bool null_lifecycle_claim_source_get_claim(void *context, struct claim *claim)
{
    (void)context;

    claim->category = CLAIM_CATEGORY_DEVICE;
    claim->subject_id = CLAIM_SUBJECT_ID_LIFECYCLE_STATE;
    claim->variant_id = CLAIM_VARIANT_ID_INTEGER;
    claim->raw_data = NULL;

    claim->variant.integer.value = PSA_LIFECYCLE_UNKNOWN;
    return true;
}
