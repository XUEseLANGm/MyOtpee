/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_GENERATE_KEY_H
#define TS_CRYPTO_GENERATE_KEY_H

#include <stdint.h>
#include "key_attributes.h"

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_generate_key_in
{
  struct ts_crypto_key_attributes attributes;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_generate_key_out
{
  uint32_t id;
};

#endif /* TS_CRYPTO_GENERATE_KEY_H */
