/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_ATTESTATION_GET_TOKEN_H
#define TS_ATTESTATION_GET_TOKEN_H

/**
 * Parameter definitions for the GET_TOKEN operation.
 *
 * Fetches a signed attestation token to allow device
 * state to be remotely verified.
 */

/* Variable length input parameter tags */
enum
{
    /* TLV tag to identify the auth_challenge
     * input parameter.
     */
    TS_ATTESTATION_GET_TOKEN_IN_TAG_AUTH_CHALLENGE = 1,
};

/* Variable length output parameter tags */
enum
{
    /* TLV tag to identify the signed token
     * output parameter.
     */
    TS_ATTESTATION_GET_TOKEN_OUT_TAG_TOKEN  = 1
};

#endif /* TS_ATTESTATION_GET_TOKEN_H */
