/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_AEAD_H
#define TS_CRYPTO_AEAD_H

#include <stdint.h>

/**
 * Protocol definitions for aead operations
 * using the packed-c serialization.
 */

/****************************************
 * aead_setup operation definition (encrypt or decrypt)
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_setup_in
{
  uint32_t key_id;
  uint32_t alg;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_setup_out
{
  uint32_t op_handle;
};

/****************************************
 * aead_generate_nonce operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_generate_nonce_in
{
  uint32_t op_handle;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_AEAD_GENERATE_NONCE_OUT_TAG_NONCE  = 1
};

/****************************************
 * aead_set_nonce operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_set_nonce_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_AEAD_SET_NONCE_IN_TAG_NONCE  = 1
};

/****************************************
 * aead_set_lengths operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_set_lengths_in
{
  uint32_t op_handle;
  uint32_t ad_length;
  uint32_t plaintext_length;
};

/****************************************
 * aead_update_ad operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_update_ad_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_AEAD_UPDATE_AD_IN_TAG_DATA  = 1
};

/****************************************
 * aead_update operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_update_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_AEAD_UPDATE_IN_TAG_DATA  = 1
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_AEAD_UPDATE_OUT_TAG_DATA  = 1
};

/****************************************
 * aead_finish operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_finish_in
{
  uint32_t op_handle;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_AEAD_FINISH_OUT_TAG_CIPHERTEXT  = 1,
    TS_CRYPTO_AEAD_FINISH_OUT_TAG_TAG  = 2
};

/****************************************
 * aead_verify operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_verify_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_AEAD_VERIFY_IN_TAG_TAG  = 1
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_AEAD_VERIFY_OUT_TAG_PLAINTEXT  = 1
};

/****************************************
 * aead_abort operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_aead_abort_in
{
  uint32_t op_handle;
};


#endif /* TS_CRYPTO_AEAD_H */
