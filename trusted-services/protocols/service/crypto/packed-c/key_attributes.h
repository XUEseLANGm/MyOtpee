/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_KEY_ATTRIBUTES_H
#define TS_CRYPTO_KEY_ATTRIBUTES_H

#include <stdint.h>

/* Key types */
#define TS_CRYPTO_KEY_TYPE_NONE                   (0x0000)
#define TS_CRYPTO_KEY_TYPE_RAW_DATA               (0x1001)
#define TS_CRYPTO_KEY_TYPE_HMAC                   (0x1100)
#define TS_CRYPTO_KEY_TYPE_DERIVE                 (0x1200)
#define TS_CRYPTO_KEY_TYPE_AES                    (0x2400)
#define TS_CRYPTO_KEY_TYPE_DES                    (0x2301)
#define TS_CRYPTO_KEY_TYPE_CAMELLIA               (0x2403)
#define TS_CRYPTO_KEY_TYPE_CHACHA20               (0x2004)
#define TS_CRYPTO_KEY_TYPE_RSA_PUBLIC_KEY         (0x4001)
#define TS_CRYPTO_KEY_TYPE_RSA_KEY_PAIR           (0x7001)

/* ECC curves for use with ECC Key types */
#define TS_CRYPTO_ECC_FAMILY_NONE                 (0x00)
#define TS_CRYPTO_ECC_FAMILY_SECP_K1              (0x17)
#define TS_CRYPTO_ECC_FAMILY_SECP_R1              (0x12)
#define TS_CRYPTO_ECC_FAMILY_SECP_R2              (0x1b)
#define TS_CRYPTO_ECC_FAMILY_SECT_K1              (0x27)
#define TS_CRYPTO_ECC_FAMILY_SECT_R1              (0x22)
#define TS_CRYPTO_ECC_FAMILY_SECT_R2              (0x2b)
#define TS_CRYPTO_ECC_FAMILY_BRAINPOOL_P_R1       (0x30)
#define TS_CRYPTO_ECC_FAMILY_MONTGOMERY           (0x41)

/* Diffie-Hellman groups for use with DH key types */
#define TS_CRYPTO_DH_FAMILY_NONE                  (0x00)
#define TS_CRYPTO_DH_FAMILY_RFC7919               (0x03)

/* Crypto algorithms */
#define TS_CRYPTO_ALG_NONE                        (0x00000000)
#define TS_CRYPTO_ALG_MD5                         (0x02000003)
#define TS_CRYPTO_ALG_RIPEMD160                   (0x02000004)
#define TS_CRYPTO_ALG_SHA_1                       (0x02000005)
#define TS_CRYPTO_ALG_SHA_224                     (0x02000008)
#define TS_CRYPTO_ALG_SHA_256                     (0x02000009)
#define TS_CRYPTO_ALG_SHA_384                     (0x0200000a)
#define TS_CRYPTO_ALG_SHA_512                     (0x0200000b)
#define TS_CRYPTO_ALG_SHA_512_224                 (0x0200000c)
#define TS_CRYPTO_ALG_SHA_512_256                 (0x0200000d)
#define TS_CRYPTO_ALG_SHA3_224                    (0x02000010)
#define TS_CRYPTO_ALG_SHA3_256                    (0x02000011)
#define TS_CRYPTO_ALG_SHA3_384                    (0x02000012)
#define TS_CRYPTO_ALG_SHA3_512                    (0x02000013)
#define TS_CRYPTO_ALG_CBC_MAC                     (0x03c00100)
#define TS_CRYPTO_ALG_CMAC                        (0x03c00200)
#define TS_CRYPTO_ALG_STREAM_CIPHER               (0x04800100)
#define TS_CRYPTO_ALG_CTR                         (0x04c01000)
#define TS_CRYPTO_ALG_CFB                         (0x04c01100)
#define TS_CRYPTO_ALG_OFB                         (0x04c01200)
#define TS_CRYPTO_ALG_XTS                         (0x0440ff00)
#define TS_CRYPTO_ALG_CBC_NO_PADDING              (0x04404000)
#define TS_CRYPTO_ALG_CBC_PKCS7                   (0x04404100)
#define TS_CRYPTO_ALG_CCM                         (0x05500100)
#define TS_CRYPTO_ALG_GCM                         (0x05500200)
#define TS_CRYPTO_ALG_CHACHA20_POLY1305           (0x05100500)
#define TS_CRYPTO_ALG_RSA_PKCS1V15_CRYPT          (0x07000200)
#define TS_CRYPTO_ALG_FFDH                        (0x09010000)
#define TS_CRYPTO_ALG_ECDH                        (0x09020000)

/* Key lifetime */
#define TS_CRYPTO_KEY_LIFETIME_VOLATILE           (0x00000000)
#define TS_CRYPTO_KEY_LIFETIME_PERSISTENT         (0x00000001)

/* Key usage constraints */
#define TS_CRYPTO_KEY_USAGE_NONE                  (0x00000000)
#define TS_CRYPTO_KEY_USAGE_EXPORT                (0x00000001)
#define TS_CRYPTO_KEY_USAGE_COPY                  (0x00000002)
#define TS_CRYPTO_KEY_USAGE_ENCRYPT               (0x00000100)
#define TS_CRYPTO_KEY_USAGE_DECRYPT               (0x00000200)
#define TS_CRYPTO_KEY_USAGE_SIGN_HASH             (0x00001000)
#define TS_CRYPTO_KEY_USAGE_VERIFY_HASH           (0x00002000)
#define TS_CRYPTO_KEY_USAGE_DERIVE                (0x00004000)

/* Key policy to define what key can be used for */
struct __attribute__ ((__packed__)) ts_crypto_key_policy
{
  uint32_t usage;
  uint32_t alg;
};

/* Key attributes object */
struct __attribute__ ((__packed__)) ts_crypto_key_attributes
{
  uint32_t type;
  uint32_t key_bits;
  uint32_t lifetime;
  uint32_t id;
  struct ts_crypto_key_policy policy;
};

#endif /* TS_CRYPTO_KEY_ATTRIBUTES_H */
