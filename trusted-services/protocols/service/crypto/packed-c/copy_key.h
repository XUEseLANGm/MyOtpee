/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_COPY_KEY_H
#define TS_CRYPTO_COPY_KEY_H

#include <stdint.h>
#include "key_attributes.h"

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_copy_key_in
{
  uint32_t source_key_id;
  struct ts_crypto_key_attributes attributes;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_copy_key_out
{
  uint32_t target_key_id;
};

#endif /* TS_CRYPTO_COPY_KEY_H */
