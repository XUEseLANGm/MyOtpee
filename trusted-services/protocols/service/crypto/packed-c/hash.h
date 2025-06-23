/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_HASH_H
#define TS_CRYPTO_HASH_H

#include <stdint.h>

/**
 * Protocol definitions for hash operations
 * using the packed-c serialization.
 */

/****************************************
 * hash_setup operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_setup_in
{
  uint32_t alg;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_setup_out
{
  uint32_t op_handle;
};

/****************************************
 * hash_update operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_update_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_HASH_UPDATE_IN_TAG_DATA  = 1
};

/****************************************
 * hash_finish operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_finish_in
{
  uint32_t op_handle;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_HASH_FINISH_OUT_TAG_HASH  = 1
};

/****************************************
 * hash_abort operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_abort_in
{
  uint32_t op_handle;
};

/****************************************
 * hash_verify operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_verify_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_HASH_VERIFY_IN_TAG_HASH  = 1
};

/****************************************
 * hash_clone operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_clone_in
{
  uint32_t source_op_handle;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_hash_clone_out
{
  uint32_t target_op_handle;
};

#endif /* TS_CRYPTO_HASH_H */
