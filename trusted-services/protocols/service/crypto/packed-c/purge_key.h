/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_PURGE_KEY_H
#define TS_CRYPTO_PURGE_KEY_H

#include <stdint.h>

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_purge_key_in
{
  uint32_t id;
};

#endif /* TS_CRYPTO_PURGE_KEY_H */
