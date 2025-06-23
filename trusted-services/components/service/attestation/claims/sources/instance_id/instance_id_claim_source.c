/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <stdint.h>
#include <psa/crypto.h>
#include <service/attestation/claims/claim.h>
#include <service/attestation/key_mngr/attest_key_mngr.h>
#include "instance_id_claim_source.h"

static bool instance_id_claim_source_get_claim(void *context, struct claim *claim);
static bool prepare_instance_id(struct instance_id_claim_source *instance);
static bool cal_iak_hash(struct instance_id_claim_source *instance,
    const uint8_t *key_buf, size_t key_len);

struct claim_source *instance_id_claim_source_init(struct instance_id_claim_source *instance)
{
    instance->base.get_claim = instance_id_claim_source_get_claim;
    instance->base.context = instance;

    instance->is_known = false;

    return &instance->base;
}

static bool instance_id_claim_source_get_claim(void *context, struct claim *claim)
{
    struct instance_id_claim_source *instance = (struct instance_id_claim_source*)context;

    if (!instance->is_known)
        instance->is_known = prepare_instance_id(instance);

    if (instance->is_known) {

        claim->category = CLAIM_CATEGORY_DEVICE;
        claim->subject_id = CLAIM_SUBJECT_ID_INSTANCE_ID;
        claim->variant_id = CLAIM_VARIANT_ID_BYTE_STRING;
        claim->raw_data = NULL;

        claim->variant.byte_string.bytes = instance->instance_id;
        claim->variant.byte_string.len = sizeof(instance->instance_id);
    }

    return instance->is_known;
}

static bool prepare_instance_id(struct instance_id_claim_source *instance)
{
    bool success = false;
    size_t key_buf_size =  attest_key_mngr_max_iak_export_size();
    uint8_t *key_buf = malloc(key_buf_size);

    if (key_buf) {

        size_t key_len;
        int status;

        status = attest_key_mngr_export_iak_public_key(key_buf, key_buf_size, &key_len);

        if (status == PSA_SUCCESS) {

            success = cal_iak_hash(instance, key_buf, key_len);

            /* Add the UEID type */
            instance->instance_id[0] = 0x01;
        }

        free(key_buf);
    }

    return success;
}

static bool cal_iak_hash(struct instance_id_claim_source *instance,
    const uint8_t *key_buf, size_t key_len)
{
    int status;
    size_t hash_len;

    psa_hash_operation_t op = psa_hash_operation_init();

    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) return false;

    status = psa_hash_update(&op, key_buf, key_len);
    if (status != PSA_SUCCESS) return false;

    status = psa_hash_finish(&op,
        &instance->instance_id[1],
        INSTANCE_ID_HASH_LEN,
        &hash_len);

    return (status == PSA_SUCCESS) && (hash_len == INSTANCE_ID_HASH_LEN);
}
