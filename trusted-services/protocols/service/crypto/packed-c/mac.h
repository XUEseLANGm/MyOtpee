/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_MAC_H
#define TS_CRYPTO_MAC_H

#include <stdint.h>

/**
 * Protocol definitions for symmetric MAC operations
 * using the packed-c serialization.
 */

/****************************************
 * mac_setup operation definition (sign or verify)
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_mac_setup_in
{
  uint32_t key_id;
  uint32_t alg;
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_crypto_mac_setup_out
{
  uint32_t op_handle;
};

/****************************************
 * mac_update operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_mac_update_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_MAC_UPDATE_IN_TAG_DATA  = 1
};

/****************************************
 * mac_sign_finish operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_mac_sign_finish_in
{
  uint32_t op_handle;
};

/* Variable length output parameter tags */
enum
{
    TS_CRYPTO_MAC_SIGN_FINISH_OUT_TAG_MAC  = 1
};

/****************************************
 * mac_verify_finish operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_mac_verify_finish_in
{
  uint32_t op_handle;
};

/* Variable length input parameter tags */
enum
{
    TS_CRYPTO_MAC_VERIFY_FINISH_IN_TAG_MAC  = 1
};

/****************************************
 * mac_abort operation definition
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_crypto_mac_abort_in
{
  uint32_t op_handle;
};

#endif /* TS_CRYPTO_MAC_H */
