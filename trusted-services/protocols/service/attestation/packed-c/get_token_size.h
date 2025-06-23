/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_ATTESTATION_GET_TOKEN_SIZE_H
#define TS_ATTESTATION_GET_TOKEN_SIZE_H

#include <stdint.h>

/**
 * Parameter definitions for the GET_TOKEN_SIZE operation.
 *
 * Returns the expected size of an attestation token when
 * a challenge of the specified length is presented.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_attestation_get_token_size_in
{
    /* The size of the challenge (nonce) that a client
     * intends to provide when requesting a new token.
     */
    uint32_t challenge_size;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_attestation_get_token_size_out
{
    /* The calculated size of the token that would be
     * returned.
     */
    uint32_t token_size;
};

#endif /* TS_ATTESTATION_GET_TOKEN_SIZE_H */
