/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_KEY_DERIVATION_H
#define TS_CRYPTO_KEY_DERIVATION_H

#include <stdint.h>
#include "key_attributes.h"

/**
 * Protocol definitions for key derivation operations
 * using the packed-c serialization.
 */


/****************************************
 * key_derivation_setup operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_setup_in
{
  uint32_t alg;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_setup_out
{
  uint32_t op_handle;
};

/****************************************
 * key_derivation_get_capacity operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_get_capacity_in
{
  uint32_t op_handle;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_get_capacity_out
{
  uint32_t capacity;
};

/****************************************
 * key_derivation_set_capacity operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_set_capacity_in
{
  uint32_t op_handle;
  uint32_t capacity;
};

/****************************************
 * key_derivation_input_bytes operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_input_bytes_in
{
  uint32_t op_handle;
  uint32_t step;
};

/* Mandatory variable length input parameter tags */
enum
{
    TS_CRYPTO_KEY_DERIVATION_INPUT_BYTES_IN_TAG_DATA  = 1
};

/****************************************
 * key_derivation_input_key operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_input_key_in
{
  uint32_t op_handle;
  uint32_t step;
  uint32_t key_id;
};

/****************************************
 * key_derivation_output_bytes operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_output_bytes_in
{
  uint32_t op_handle;
  uint32_t output_len;
};

/* Mandatory variable length output parameter tags */
enum
{
    TS_CRYPTO_KEY_DERIVATION_OUTPUT_BYTES_OUT_TAG_DATA  = 1
};

/****************************************
 * key_derivation_output_key operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_output_key_in
{
  uint32_t op_handle;
  struct ts_crypto_key_attributes attributes;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_output_key_out
{
  uint32_t key_id;
};

/****************************************
 * key_derivation_abort operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_abort_in
{
  uint32_t op_handle;
};

/****************************************
 * key_derivation_key_agreement operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_key_derivation_key_agreement_in
{
  uint32_t op_handle;
  uint32_t step;
  uint32_t private_key_id;
};

/* Mandatory variable length input parameter tags */
enum
{
    TS_CRYPTO_KEY_DERIVATION_KEY_AGREEMENT_IN_TAG_PEER_KEY  = 1
};

/****************************************
 * raw_key_agreement operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_raw_key_agreement_in
{
  uint32_t alg;
  uint32_t private_key_id;
};

/* Mandatory variable length input parameter tags */
enum
{
    TS_CRYPTO_RAW_KEY_AGREEMENT_IN_TAG_PEER_KEY  = 1
};

/* Mandatory variable length output parameter tags */
enum
{
    TS_CRYPTO_RAW_KEY_AGREEMENT_OUT_TAG_OUTPUT  = 1
};

#endif /* TS_CRYPTO_KEY_DERIVATION_H */
