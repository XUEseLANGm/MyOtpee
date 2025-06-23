/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * An attestation reporter that creates attestation reports using claims
 * collected from claim sources registered with the local claims regsiter.
 * Reports are serialized using CBOR and signed using COSE in-line with
 * EAT conventions.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <psa/error.h>
#include <psa/initial_attestation.h>
#include <service/attestation/reporter/attest_report.h>
#include <service/attestation/claims/claims_register.h>
#include <service/attestation/reporter/eat/eat_serializer.h>
#include <service/attestation/reporter/eat/eat_signer.h>
#include <service/attestation/key_mngr/attest_key_mngr.h>

/* Local defines */
#define MAX_DEVICE_CLAIMS       (50)
#define MAX_SW_CLAIMS           (50)

static bool validate_challenge(size_t len);
static void add_auth_challenge_claim(struct claim_vector *v, const uint8_t *data, size_t len);
static void add_client_id_claim(struct claim_vector *v, int32_t client_id);
static void add_no_sw_claim(struct claim_vector *v);


int attest_report_create(int32_t client_id,
    const uint8_t *auth_challenge_data, size_t auth_challenge_len,
    const uint8_t **report, size_t *report_len)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    struct claim_vector device_claims;
    struct claim_vector sw_claims;
    psa_key_id_t key_id;

    *report = NULL;
    *report_len = 0;

    if (!validate_challenge(auth_challenge_len)) return PSA_ERROR_INVALID_ARGUMENT;

    status = attest_key_mngr_get_iak_id(&key_id);
    if (status != PSA_SUCCESS) return status;

    claim_vector_init(&device_claims, MAX_DEVICE_CLAIMS);
    claim_vector_init(&sw_claims, MAX_SW_CLAIMS);

    /* Add claims related to the requester */
    add_auth_challenge_claim(&device_claims, auth_challenge_data, auth_challenge_len);
    add_client_id_claim(&device_claims, client_id);

    /* Collate all other claims to include in the report */
    claims_register_query_by_category(CLAIM_CATEGORY_DEVICE, &device_claims);
    claims_register_query_by_category(CLAIM_CATEGORY_VERIFICATION_SERVICE, &device_claims);
    claims_register_query_by_category(CLAIM_CATEGORY_BOOT_MEASUREMENT, &sw_claims);

    /* And if there aren't any sw claims, indicate in report */
    if (!sw_claims.size) add_no_sw_claim(&device_claims);

    /* Serialize and sign the collated claims to create the final EAT token */
    const uint8_t *unsigned_token = NULL;
    size_t unsigned_token_len = 0;
    status = eat_serialize(&device_claims, &sw_claims,
                    &unsigned_token, &unsigned_token_len);

    if (status == PSA_SUCCESS) {
        status = eat_sign(key_id,
                    unsigned_token, unsigned_token_len,
                    report, report_len);
    }

    /* Free resource used */
    free((void*)unsigned_token);
    claim_vector_deinit(&device_claims);
    claim_vector_deinit(&sw_claims);

    return status;
}

void attest_report_destroy(const uint8_t *report)
{
    free((void*)report);
}

static bool validate_challenge(size_t len)
{
    /* Only allow specific challenge lengths */
    return
        (len == PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32) ||
        (len == PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48) ||
        (len == PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64);
}

static void add_auth_challenge_claim(struct claim_vector *v, const uint8_t *data, size_t len)
{
    struct claim claim;

    claim.subject_id = CLAIM_SUBJECT_ID_AUTH_CHALLENGE;
    claim.variant_id = CLAIM_VARIANT_ID_BYTE_STRING;
    claim.raw_data = NULL;

    claim.variant.byte_string.bytes = data;
    claim.variant.byte_string.len = len;

    claim_vector_push_back(v, &claim);
}

static void add_client_id_claim(struct claim_vector *v, int32_t client_id)
{
    struct claim claim;

    claim.subject_id = CLAIM_SUBJECT_ID_CLIENT_ID;
    claim.variant_id = CLAIM_VARIANT_ID_INTEGER;
    claim.raw_data = NULL;

    claim.variant.integer.value = client_id;

    claim_vector_push_back(v, &claim);
}

static void add_no_sw_claim(struct claim_vector *v)
{
    struct claim claim;

    claim.subject_id = CLAIM_SUBJECT_ID_NO_SW_MEASUREMENTS;
    claim.variant_id = CLAIM_VARIANT_ID_INTEGER;
    claim.raw_data = NULL;

    claim.variant.integer.value = 1;

    claim_vector_push_back(v, &claim);
}
