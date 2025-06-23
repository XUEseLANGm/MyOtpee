/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_CIPHER_H
#define TS_CRYPTO_CIPHER_H

#include <stdint.h>

/**
 * Protocol definitions for symmetric cipher operations
 * using the packed-c serialization.
 */

/****************************************
 * cipher_setup operation definition (encrypt or decrypt)
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_setup_in
{
  uint32_t key_id;
  uint32_t alg;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_setup_out
{
  uint32_t op_handle;
};

/****************************************
 * cipher_generate_iv operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_generate_iv_in
{
  uint32_t op_handle;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_CIPHER_GENERATE_IV_OUT_TAG_IV  = 1
};

/****************************************
 * cipher_set_iv operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_set_iv_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_CIPHER_SET_IV_IN_TAG_IV  = 1
};

/****************************************
 * cipher_update operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_update_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_CIPHER_UPDATE_IN_TAG_DATA  = 1
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_CIPHER_UPDATE_OUT_TAG_DATA  = 1
};

/****************************************
 * cipher_finish operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_finish_in
{
  uint32_t op_handle;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_CIPHER_FINISH_OUT_TAG_DATA  = 1
};

/****************************************
 * cipher_abort operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_cipher_abort_in
{
  uint32_t op_handle;
};

#endif /* TS_CRYPTO_CIPHER_H */
