/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <psa/crypto.h>
#include <protocols/service/crypto/packed-c/opcodes.h>
#include <service/crypto/protobuf/opcodes.pb.h>
#include <CppUTest/TestHarness.h>

/*
 * Check alignment of Crypto service opcode definitions
 */
TEST_GROUP(CryptoProtocolOpcodeChecks)
{

};

TEST(CryptoProtocolOpcodeChecks, checkPackedcToProtobuf)
{
	CHECK_EQUAL(TS_CRYPTO_OPCODE_GENERATE_KEY, ts_crypto_Opcode_GENERATE_KEY);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_DESTROY_KEY, ts_crypto_Opcode_DESTROY_KEY);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_EXPORT_KEY, ts_crypto_Opcode_EXPORT_KEY);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_EXPORT_PUBLIC_KEY, ts_crypto_Opcode_EXPORT_PUBLIC_KEY);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_IMPORT_KEY, ts_crypto_Opcode_IMPORT_KEY);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_SIGN_HASH, ts_crypto_Opcode_SIGN_HASH);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_VERIFY_HASH, ts_crypto_Opcode_VERIFY_HASH);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_ASYMMETRIC_DECRYPT, ts_crypto_Opcode_ASYMMETRIC_DECRYPT);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_ASYMMETRIC_ENCRYPT, ts_crypto_Opcode_ASYMMETRIC_ENCRYPT);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_GENERATE_RANDOM, ts_crypto_Opcode_GENERATE_RANDOM);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_SIGN_MESSAGE, ts_crypto_Opcode_SIGN_MESSAGE);
	CHECK_EQUAL(TS_CRYPTO_OPCODE_VERIFY_MESSAGE, ts_crypto_Opcode_VERIFY_MESSAGE);
}
