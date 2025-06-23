/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <qcbor/qcbor_encode.h>
#include <psa/error.h>
#include <protocols/service/attestation/packed-c/eat.h>
#include <service/attestation/claims/claim.h>
#include "eat_serializer.h"

static bool alloc_encode_buffer(const struct claim_vector *device_claims,
    const struct claim_vector *sw_claims, UsefulBuf *encode_buffer);

static void encode_claim(QCBOREncodeContext *encode_ctx, const struct claim *claim);
static int eat_label(enum claim_subject_id subject_id);
static int qcbor_to_psa_status(QCBORError qcbor_err);

int eat_serialize(const struct claim_vector *device_claims,
    const struct claim_vector *sw_claims,
    const uint8_t **token, size_t *token_len)
{
    UsefulBuf encode_buffer;

    if (!alloc_encode_buffer(device_claims, sw_claims, &encode_buffer))
        return PSA_ERROR_INSUFFICIENT_MEMORY;

    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, encode_buffer);
    QCBOREncode_OpenMap(&encode_ctx);

    /* Encode all device claims */
    for (size_t i = 0; i < device_claims->size; ++i) {

        encode_claim(&encode_ctx, &device_claims->claims[i]);
    }

    /* Add child array of sw claims if there are any */
    if (sw_claims->size) {

        QCBOREncode_OpenArrayInMapN(&encode_ctx, EAT_ARM_PSA_CLAIM_ID_SW_COMPONENTS);

        for (size_t i = 0; i < sw_claims->size; ++i) {

            encode_claim(&encode_ctx, &sw_claims->claims[i]);
        }

        QCBOREncode_CloseArray(&encode_ctx);
    }

    QCBOREncode_CloseMap(&encode_ctx);

    /* Finalize the encoding to create the CBOR serialized token */
    UsefulBufC encoded_cbor;
    QCBORError qcbor_error;
    qcbor_error = QCBOREncode_Finish(&encode_ctx, &encoded_cbor);

    if (qcbor_error == QCBOR_SUCCESS) {

        *token = encoded_cbor.ptr;
        *token_len = encoded_cbor.len;
    }
    else {

        free(encode_buffer.ptr);
        *token = NULL;
        *token_len = 0;
    }

    return qcbor_to_psa_status(qcbor_error);
}

static bool alloc_encode_buffer(const struct claim_vector *device_claims,
    const struct claim_vector *sw_claims, UsefulBuf *encode_buffer)
{
    // todo estimate required space
    (void)device_claims;
    (void)sw_claims;

    encode_buffer->len = 4096;
    encode_buffer->ptr = malloc(encode_buffer->len);

    return encode_buffer->ptr;
}

static void encode_claim(QCBOREncodeContext *encode_ctx, const struct claim *claim)
{
    int label = eat_label(claim->subject_id);

    switch (claim->variant_id)
    {
        case CLAIM_VARIANT_ID_INTEGER:
        {
            QCBOREncode_AddInt64ToMapN(encode_ctx, label, claim->variant.integer.value);
            break;
        }
        case CLAIM_VARIANT_ID_TEXT_STRING:
        {
            QCBOREncode_AddSZStringToMapN(encode_ctx, label, claim->variant.text_string.string);
            break;
        }
        case CLAIM_VARIANT_ID_BYTE_STRING:
        {
            UsefulBufC byte_string;
            byte_string.ptr = claim->variant.byte_string.bytes;
            byte_string.len = claim->variant.byte_string.len;
            QCBOREncode_AddBytesToMapN(encode_ctx, label, byte_string);
            break;
        }
        case CLAIM_VARIANT_ID_MEASUREMENT:
        {
            UsefulBufC byte_string;
            QCBOREncode_OpenMap(encode_ctx);
            QCBOREncode_AddSZStringToMapN(encode_ctx,
                EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_TYPE,
                claim->variant.measurement.id.string);

            byte_string.ptr = claim->variant.measurement.digest.bytes;
            byte_string.len = claim->variant.measurement.digest.len;
            QCBOREncode_AddBytesToMapN(encode_ctx,
                EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_VALUE, byte_string);
            QCBOREncode_CloseMap(encode_ctx);
            break;
        }
        default:
            break;
    }
}

static int eat_label(enum claim_subject_id subject_id)
{
    int label = 0;

    switch (subject_id)
    {
        case CLAIM_SUBJECT_ID_AUTH_CHALLENGE:
            label = EAT_ARM_PSA_CLAIM_ID_CHALLENGE;
            break;
        case CLAIM_SUBJECT_ID_INSTANCE_ID:
            label = EAT_ARM_PSA_CLAIM_ID_INSTANCE_ID;
            break;
        case CLAIM_SUBJECT_ID_VERIFICATION_SERVICE_INDICATOR:
            label = EAT_ARM_PSA_CLAIM_ID_VERIFIER;
            break;
        case CLAIM_SUBJECT_ID_PROFILE_DEFINITION:
            label = EAT_ARM_PSA_CLAIM_ID_PROFILE_DEFINITION;
            break;
        case CLAIM_SUBJECT_ID_IMPLEMENTATION_ID:
            label = EAT_ARM_PSA_CLAIM_ID_IMPLEMENTATION_ID;
            break;
        case CLAIM_SUBJECT_ID_CLIENT_ID:
            label = EAT_ARM_PSA_CLAIM_ID_CLIENT_ID;
            break;
        case CLAIM_SUBJECT_ID_LIFECYCLE_STATE:
            label = EAT_ARM_PSA_CLAIM_ID_SECURITY_LIFECYCLE;
            break;
        case CLAIM_SUBJECT_ID_HW_VERSION:
            label = EAT_ARM_PSA_CLAIM_ID_HW_VERSION;
            break;
        case CLAIM_SUBJECT_ID_BOOT_SEED:
            label = EAT_ARM_PSA_CLAIM_ID_BOOT_SEED;
            break;
        case CLAIM_SUBJECT_ID_NO_SW_MEASUREMENTS:
            label = EAT_ARM_PSA_CLAIM_ID_NO_SW_COMPONENTS;
            break;
        case CLAIM_SUBJECT_ID_SW_COMPONENT:
            label = EAT_ARM_PSA_CLAIM_ID_SW_COMPONENTS;
            break;
        default:
            break;
    }

    return label;
}

static int qcbor_to_psa_status(QCBORError qcbor_err)
{
    if (qcbor_err == QCBOR_SUCCESS)                 return PSA_SUCCESS;
    if (qcbor_err == QCBOR_ERR_BUFFER_TOO_SMALL)    return PSA_ERROR_BUFFER_TOO_SMALL;

    return PSA_ERROR_PROGRAMMER_ERROR;
}
