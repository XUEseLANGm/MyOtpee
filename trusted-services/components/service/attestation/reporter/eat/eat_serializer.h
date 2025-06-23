/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_EAT_SERIALIZER_H
#define PSA_EAT_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <service/attestation/claims/claim_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Serialize the collated set of claims
 *
 *  Serializes the claims into a CBOR document using PSA defined
 *  EAT custom claims to identify claim objects.  The output
 *  token is encoded as cbor but is not signed.
 *
 * \param[in] device_claims         Collated device claims
 * \param[in] sw_claims             Collated software claims
 * \param[out] token                The serialized token
 * \param[out] token_len            The length of the token
 *
 * \return Operation status
 */
int eat_serialize(const struct claim_vector *device_claims,
    const struct claim_vector *sw_claims,
    const uint8_t **token, size_t *token_len);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PSA_EAT_SERIALIZER_H */
