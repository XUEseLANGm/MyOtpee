/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_GENERATE_RANDOM_H
#define TS_CRYPTO_GENERATE_RANDOM_H

#include <stdint.h>

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_generate_random_in
{
  uint32_t size;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_GENERATE_RANDOM_OUT_TAG_RANDOM_BYTES  = 1
};

#endif /* TS_CRYPTO_GENERATE_RANDOM_H */