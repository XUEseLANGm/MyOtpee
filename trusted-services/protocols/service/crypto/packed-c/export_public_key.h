/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_EXPORT_PUBLIC_KEY_H
#define TS_CRYPTO_EXPORT_PUBLIC_KEY_H

#include <stdint.h>

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_export_public_key_in
{
  uint32_t id;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_EXPORT_PUBLIC_KEY_OUT_TAG_DATA  = 1
};

#endif /* TS_CRYPTO_EXPORT_PUBLIC_KEY_H */