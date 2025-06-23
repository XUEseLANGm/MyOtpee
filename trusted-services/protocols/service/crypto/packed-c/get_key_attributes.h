/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_GET_KEY_ATTRIBUTES_H
#define TS_CRYPTO_GET_KEY_ATTRIBUTES_H

#include <stdint.h>
#include "key_attributes.h"

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_get_key_attributes_in
{
  uint32_t id;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_get_key_attributes_out
{
  struct ts_crypto_key_attributes attributes;
};

#endif /* TS_CRYPTO_GET_KEY_ATTRIBUTES_H */
