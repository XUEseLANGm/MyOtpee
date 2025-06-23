/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_ASYMMETRIC_DECRYPT_H
#define TS_CRYPTO_ASYMMETRIC_DECRYPT_H

#include <stdint.h>

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_asymmetric_decrypt_in
{
  uint32_t id;
  uint32_t alg;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_ASYMMETRIC_DECRYPT_IN_TAG_CIPHERTEXT  = 1,
    TS_CRYPTO_ASYMMETRIC_DECRYPT_IN_TAG_SALT  = 2
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_ASYMMETRIC_DECRYPT_OUT_TAG_PLAINTEXT  = 1
};

#endif /* TS_CRYPTO_ASYMMETRIC_DECRYPT_H */