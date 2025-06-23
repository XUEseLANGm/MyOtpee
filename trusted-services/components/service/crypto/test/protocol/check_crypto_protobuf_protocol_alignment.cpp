/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <psa/crypto.h>
#include <service/crypto/protobuf/key_attributes.pb.h>
#include <CppUTest/TestHarness.h>

/*
 * Check alignment of Crypto service protobuf protocol definitions for
 * alignment with PSA C API definitions.
 */
TEST_GROUP(CryptoProtocolProtobufChecks)
{

};

TEST(CryptoProtocolProtobufChecks, checkKeyType)
{
    /*
     * Check alignment between PSA and protobuf key type definitions
     */
    CHECK_EQUAL(PSA_KEY_TYPE_RAW_DATA, ts_crypto_KeyType_KEY_TYPE_RAW_DATA);
    CHECK_EQUAL(PSA_KEY_TYPE_HMAC, ts_crypto_KeyType_KEY_TYPE_HMAC);
    CHECK_EQUAL(PSA_KEY_TYPE_DERIVE, ts_crypto_KeyType_KEY_TYPE_DERIVE);
    CHECK_EQUAL(PSA_KEY_TYPE_AES, ts_crypto_KeyType_KEY_TYPE_AES);
    CHECK_EQUAL(PSA_KEY_TYPE_DES, ts_crypto_KeyType_KEY_TYPE_DES);
    CHECK_EQUAL(PSA_KEY_TYPE_CAMELLIA, ts_crypto_KeyType_KEY_TYPE_CAMELLIA);
    CHECK_EQUAL(PSA_KEY_TYPE_CHACHA20, ts_crypto_KeyType_KEY_TYPE_CHACHA20);
    CHECK_EQUAL(PSA_KEY_TYPE_RSA_PUBLIC_KEY, ts_crypto_KeyType_KEY_TYPE_RSA_PUBLIC_KEY);
    CHECK_EQUAL(PSA_KEY_TYPE_RSA_KEY_PAIR, ts_crypto_KeyType_KEY_TYPE_RSA_KEY_PAIR);
}

TEST(CryptoProtocolProtobufChecks, checkEccCurve)
{
    /*
     * ECC curves for use with ECC Key types
     */
    CHECK_EQUAL(PSA_ECC_FAMILY_SECP_K1, ts_crypto_EccCurve_ECC_FAMILY_SECP_K1);
    CHECK_EQUAL(PSA_ECC_FAMILY_SECP_R1, ts_crypto_EccCurve_ECC_FAMILY_SECP_R1);
    CHECK_EQUAL(PSA_ECC_FAMILY_SECP_R2, ts_crypto_EccCurve_ECC_FAMILY_SECP_R2);
    CHECK_EQUAL(PSA_ECC_FAMILY_SECT_K1, ts_crypto_EccCurve_ECC_FAMILY_SECT_K1);
    CHECK_EQUAL(PSA_ECC_FAMILY_SECT_R1, ts_crypto_EccCurve_ECC_FAMILY_SECT_R1);
    CHECK_EQUAL(PSA_ECC_FAMILY_SECT_R2, ts_crypto_EccCurve_ECC_FAMILY_SECT_R2);
    CHECK_EQUAL(PSA_ECC_FAMILY_BRAINPOOL_P_R1, ts_crypto_EccCurve_ECC_FAMILY_BRAINPOOL_P_R1);
    CHECK_EQUAL(PSA_ECC_FAMILY_MONTGOMERY, ts_crypto_EccCurve_ECC_FAMILY_MONTGOMERY);
}

TEST(CryptoProtocolProtobufChecks, checkDhGroup)
{
    /*
     * Diffie-Hellman groups for use with DH key types
     */
    CHECK_EQUAL(PSA_DH_FAMILY_RFC7919, ts_crypto_DhGroup_DH_FAMILY_RFC7919);
}

TEST(CryptoProtocolProtobufChecks, checkAlg)
{
    /*
     * Crypto algorithms
     */
    CHECK_EQUAL(PSA_ALG_MD5, ts_crypto_Alg_ALG_MD5);
    CHECK_EQUAL(PSA_ALG_RIPEMD160, ts_crypto_Alg_ALG_RIPEMD160);
    CHECK_EQUAL(PSA_ALG_SHA_1, ts_crypto_Alg_ALG_SHA_1);
    CHECK_EQUAL(PSA_ALG_SHA_224, ts_crypto_Alg_ALG_SHA_224);
    CHECK_EQUAL(PSA_ALG_SHA_256, ts_crypto_Alg_ALG_SHA_256);
    CHECK_EQUAL(PSA_ALG_SHA_384, ts_crypto_Alg_ALG_SHA_384);
    CHECK_EQUAL(PSA_ALG_SHA_512, ts_crypto_Alg_ALG_SHA_512);
    CHECK_EQUAL(PSA_ALG_SHA_512_224, ts_crypto_Alg_ALG_SHA_512_224);
    CHECK_EQUAL(PSA_ALG_SHA_512_256, ts_crypto_Alg_ALG_SHA_512_256);
    CHECK_EQUAL(PSA_ALG_SHA3_224, ts_crypto_Alg_ALG_SHA3_224);
    CHECK_EQUAL(PSA_ALG_SHA3_256, ts_crypto_Alg_ALG_SHA3_256);
    CHECK_EQUAL(PSA_ALG_SHA3_384, ts_crypto_Alg_ALG_SHA3_384);
    CHECK_EQUAL(PSA_ALG_SHA3_512, ts_crypto_Alg_ALG_SHA3_512);
    CHECK_EQUAL(PSA_ALG_CBC_MAC, ts_crypto_Alg_ALG_CBC_MAC);
    CHECK_EQUAL(PSA_ALG_CMAC, ts_crypto_Alg_ALG_CMAC);
    CHECK_EQUAL(PSA_ALG_STREAM_CIPHER, ts_crypto_Alg_ALG_STREAM_CIPHER);
    CHECK_EQUAL(PSA_ALG_CTR, ts_crypto_Alg_ALG_CTR);
    CHECK_EQUAL(PSA_ALG_CFB, ts_crypto_Alg_ALG_CFB);
    CHECK_EQUAL(PSA_ALG_OFB, ts_crypto_Alg_ALG_OFB);
    CHECK_EQUAL(PSA_ALG_XTS, ts_crypto_Alg_ALG_XTS);
    CHECK_EQUAL(PSA_ALG_CBC_NO_PADDING, ts_crypto_Alg_ALG_CBC_NO_PADDING);
    CHECK_EQUAL(PSA_ALG_CBC_PKCS7, ts_crypto_Alg_ALG_CBC_PKCS7);
    CHECK_EQUAL(PSA_ALG_CCM, ts_crypto_Alg_ALG_CCM);
    CHECK_EQUAL(PSA_ALG_GCM, ts_crypto_Alg_ALG_GCM);
    CHECK_EQUAL(PSA_ALG_CHACHA20_POLY1305, ts_crypto_Alg_ALG_CHACHA20_POLY1305);
    CHECK_EQUAL(PSA_ALG_RSA_PKCS1V15_CRYPT, ts_crypto_Alg_ALG_RSA_PKCS1V15_CRYPT);
    CHECK_EQUAL(PSA_ALG_FFDH, ts_crypto_Alg_ALG_FFDH);
    CHECK_EQUAL(PSA_ALG_ECDH, ts_crypto_Alg_ALG_ECDH);
}

TEST(CryptoProtocolProtobufChecks, checkKeyLifetime)
{
    /*
     * Key lifetime
     */
    CHECK_EQUAL(PSA_KEY_LIFETIME_VOLATILE, ts_crypto_KeyLifetime_KEY_LIFETIME_VOLATILE);
    CHECK_EQUAL(PSA_KEY_LIFETIME_PERSISTENT, ts_crypto_KeyLifetime_KEY_LIFETIME_PERSISTENT);
}

TEST(CryptoProtocolProtobufChecks, checkKeyUsage)
{
    /*
     * Key usage constraints
     */
    CHECK_EQUAL(PSA_KEY_USAGE_EXPORT, ts_crypto_KeyUsage_KEY_USAGE_EXPORT);
    CHECK_EQUAL(PSA_KEY_USAGE_COPY, ts_crypto_KeyUsage_KEY_USAGE_COPY);
    CHECK_EQUAL(PSA_KEY_USAGE_ENCRYPT, ts_crypto_KeyUsage_KEY_USAGE_ENCRYPT);
    CHECK_EQUAL(PSA_KEY_USAGE_DECRYPT, ts_crypto_KeyUsage_KEY_USAGE_DECRYPT);
    CHECK_EQUAL(PSA_KEY_USAGE_SIGN_HASH, ts_crypto_KeyUsage_KEY_USAGE_SIGN_HASH);
    CHECK_EQUAL(PSA_KEY_USAGE_VERIFY_HASH, ts_crypto_KeyUsage_KEY_USAGE_VERIFY_HASH);
    CHECK_EQUAL(PSA_KEY_USAGE_DERIVE, ts_crypto_KeyUsage_KEY_USAGE_DERIVE);
}
