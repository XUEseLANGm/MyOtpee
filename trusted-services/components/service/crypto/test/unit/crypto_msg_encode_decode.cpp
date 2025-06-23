/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <CppUTest/TestHarness.h>
#include <service/crypto/protobuf/generate_key.pb.h>
#include <service/crypto/protobuf/export_public_key.pb.h>
#include <service/crypto/protobuf/sign_hash.pb.h>
#include <pb.h>
#include <pb_encode.h>
#include <pb_decode.h>


TEST_GROUP(CryptoMsgTests) {

	void setup() {
        print_info = false;
    }

	/* Nanopb encode/decode methods */
	static bool encode_byte_array(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {

		const pb_bytes_array_t *byte_array = (const pb_bytes_array_t *)*arg;
		if (!pb_encode_tag_for_field(stream, field)) return false;

		return pb_encode_string(stream, byte_array->bytes, byte_array->size);
	}

	static bool decode_byte_array(pb_istream_t *stream, const pb_field_t *field, void **arg) {

		(void)field;
		pb_bytes_array_t *byte_array = (pb_bytes_array_t *)*arg;
		if (stream->bytes_left > byte_array->size) return false;

		return pb_read(stream, byte_array->bytes, stream->bytes_left);
	}

	static pb_callback_t out_byte_array(const pb_bytes_array_t *byte_array) {

		pb_callback_t callback;
		callback.funcs.encode = encode_byte_array;
		callback.arg = (void*)byte_array;

		return callback;
	}

	static pb_callback_t in_byte_array(pb_bytes_array_t *byte_array) {

		pb_callback_t callback;
		callback.funcs.decode = decode_byte_array;
		callback.arg = (void*)byte_array;
		return callback;
	}

	bool print_info;
};

TEST(CryptoMsgTests, GenerateKeyInMsgTest) {
	/* Sender - set values and serialize */
	ts_crypto_GenerateKeyIn sent_msg = ts_crypto_GenerateKeyIn_init_default;
	ts_crypto_KeyAttributes sent_key_attributes = ts_crypto_KeyAttributes_init_default;

	sent_key_attributes.type = ts_crypto_EccCurve_ECC_FAMILY_SECP_R1;

	sent_key_attributes.key_bits = 256;
	sent_key_attributes.lifetime = ts_crypto_KeyLifetime_KEY_LIFETIME_PERSISTENT;
	sent_key_attributes.id = 3;

	sent_key_attributes.has_policy = true;
	sent_key_attributes.policy.usage = ts_crypto_KeyUsage_KEY_USAGE_SIGN_HASH;
	sent_key_attributes.policy.alg = ts_crypto_Alg_ALG_SHA_256;

	sent_msg.attributes = sent_key_attributes;
	sent_msg.has_attributes = true;

	size_t sent_msg_len;
	CHECK(pb_get_encoded_size(&sent_msg_len, ts_crypto_GenerateKeyIn_fields, &sent_msg));
	uint8_t *sent_msg_buf = (uint8_t*)malloc(sent_msg_len);
	CHECK(sent_msg_len > 0);
	CHECK(sent_msg_buf);

	pb_ostream_t ostream = pb_ostream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK(pb_encode(&ostream, ts_crypto_GenerateKeyIn_fields, &sent_msg));
	CHECK_EQUAL(sent_msg_len, ostream.bytes_written);

	/* Receiver - deserialize and use values */
	ts_crypto_GenerateKeyIn recv_msg = ts_crypto_GenerateKeyIn_init_default;

	pb_istream_t istream = pb_istream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK_EQUAL(sent_msg_len, istream.bytes_left);
	CHECK(pb_decode(&istream, ts_crypto_GenerateKeyIn_fields, &recv_msg));
	CHECK_EQUAL(0, istream.bytes_left);

	free(sent_msg_buf);

	CHECK(recv_msg.has_attributes);
	CHECK_EQUAL(sent_key_attributes.type, recv_msg.attributes.type);
	CHECK_EQUAL(sent_key_attributes.key_bits, recv_msg.attributes.key_bits);
	CHECK_EQUAL(sent_key_attributes.lifetime, recv_msg.attributes.lifetime);
	CHECK_EQUAL(sent_key_attributes.id, recv_msg.attributes.id);

	CHECK(recv_msg.attributes.has_policy);
	CHECK_EQUAL(sent_key_attributes.policy.usage, recv_msg.attributes.policy.usage);
	CHECK_EQUAL(sent_key_attributes.policy.alg, recv_msg.attributes.policy.alg);

	if (print_info) {
		printf("Serialized op_export_public_key len: %ld\n", sent_msg_len);
	}
}

TEST(CryptoMsgTests, ExportPublicKeyInMsgTest) {
	/* Sender - set values and serialize */
	ts_crypto_ExportPublicKeyIn sent_msg = ts_crypto_ExportPublicKeyIn_init_default;

	sent_msg.id = 55;

	size_t sent_msg_len;
	CHECK(pb_get_encoded_size(&sent_msg_len, ts_crypto_ExportPublicKeyIn_fields, &sent_msg));
	uint8_t *sent_msg_buf = (uint8_t*)malloc(sent_msg_len);
	CHECK(sent_msg_len > 0);
	CHECK(sent_msg_buf);

	pb_ostream_t ostream = pb_ostream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK(pb_encode(&ostream, ts_crypto_ExportPublicKeyIn_fields, &sent_msg));
	CHECK_EQUAL(sent_msg_len, ostream.bytes_written);

	/* Receiver - deserialize and use values */
	ts_crypto_ExportPublicKeyIn recv_msg = ts_crypto_ExportPublicKeyIn_init_default;

	pb_istream_t istream = pb_istream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK_EQUAL(sent_msg_len, istream.bytes_left);
	CHECK(pb_decode(&istream, ts_crypto_ExportPublicKeyIn_fields, &recv_msg));
	CHECK_EQUAL(0, istream.bytes_left);

	CHECK_EQUAL(sent_msg.id, recv_msg.id);

	free(sent_msg_buf);

	if (print_info) {
		printf("Serialized op_export_public_key len: %ld\n", sent_msg_len);
	}
}

TEST(CryptoMsgTests, ExportPublicKeyOutMsgTest) {
	/* Sender - set values and serialize */
	ts_crypto_ExportPublicKeyOut sent_msg = ts_crypto_ExportPublicKeyOut_init_default;

	PB_BYTES_ARRAY_T(5) example_key = {5, {0x31, 0x32, 0x33, 0x34, 0x35}};
	sent_msg.data = out_byte_array((const pb_bytes_array_t *)&example_key);

	size_t sent_msg_len;
	CHECK(pb_get_encoded_size(&sent_msg_len, ts_crypto_ExportPublicKeyOut_fields, &sent_msg));
	uint8_t *sent_msg_buf = (uint8_t*)malloc(sent_msg_len);
	CHECK(sent_msg_len > 0);
	CHECK(sent_msg_buf);

	pb_ostream_t ostream = pb_ostream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK(pb_encode(&ostream, ts_crypto_ExportPublicKeyOut_fields, &sent_msg));
	CHECK_EQUAL(sent_msg_len, ostream.bytes_written);

	/* Receiver - deserialize and use values */
	PB_BYTES_ARRAY_T(5) recv_key = {5, {0}};
	ts_crypto_ExportPublicKeyOut recv_msg = ts_crypto_ExportPublicKeyOut_init_default;
	recv_msg.data = in_byte_array((pb_bytes_array_t *)&recv_key);

	pb_istream_t istream = pb_istream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK_EQUAL(sent_msg_len, istream.bytes_left);
	CHECK(pb_decode(&istream, ts_crypto_ExportPublicKeyOut_fields, &recv_msg));
	CHECK_EQUAL(0, istream.bytes_left);

	free(sent_msg_buf);

	CHECK_EQUAL(example_key.size, recv_key.size);
	CHECK(memcmp(example_key.bytes, recv_key.bytes, example_key.size) == 0);

	if (print_info) {
		printf("Serialized result_export_public_key len: %ld\n", sent_msg_len);
	}
}

TEST(CryptoMsgTests, SignHashInMsgTest) {
	/* Sender - set values and serialize */
	ts_crypto_SignHashIn sent_msg = ts_crypto_SignHashIn_init_default;

	PB_BYTES_ARRAY_T(6) msg_to_sign = {6, {0x34, 0x32, 0x33, 0x34, 0x35, 0x36}};
	sent_msg.hash = out_byte_array((const pb_bytes_array_t *)&msg_to_sign);

	sent_msg.id = 71;
	sent_msg.alg = ts_crypto_Alg_ALG_SHA_256;

	size_t sent_msg_len;
	CHECK(pb_get_encoded_size(&sent_msg_len, ts_crypto_SignHashIn_fields, &sent_msg));
	uint8_t *sent_msg_buf = (uint8_t*)malloc(sent_msg_len);
	CHECK(sent_msg_len > 0);
	CHECK(sent_msg_buf);

	pb_ostream_t ostream = pb_ostream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK(pb_encode(&ostream, ts_crypto_SignHashIn_fields, &sent_msg));
	CHECK_EQUAL(sent_msg_len, ostream.bytes_written);

	/* Receiver - deserialize and use values */
	PB_BYTES_ARRAY_T(6) recv_msg_to_sign = {6, {0}};
	ts_crypto_SignHashIn recv_msg = ts_crypto_SignHashIn_init_default;
	recv_msg.hash = in_byte_array((pb_bytes_array_t *)&recv_msg_to_sign);

	pb_istream_t istream = pb_istream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK_EQUAL(sent_msg_len, istream.bytes_left);
	CHECK(pb_decode(&istream, ts_crypto_SignHashIn_fields, &recv_msg));
	CHECK_EQUAL(0, istream.bytes_left);

	free(sent_msg_buf);

	CHECK_EQUAL(sent_msg.id, recv_msg.id);
	CHECK_EQUAL(sent_msg.alg, recv_msg.alg);

	CHECK_EQUAL(msg_to_sign.size, recv_msg_to_sign.size);
	CHECK(memcmp(msg_to_sign.bytes, recv_msg_to_sign.bytes, msg_to_sign.size) == 0);

	if (print_info) {
		printf("Serialized op_asym_sign len: %ld\n", sent_msg_len);
	}
}

TEST(CryptoMsgTests, SignHashOutMsgTest) {
	/* Sender - set values and serialize */
	ts_crypto_SignHashOut sent_msg = ts_crypto_SignHashOut_init_default;

	PB_BYTES_ARRAY_T(10) example_signature = {10, {0x01, 0x02, 0x5a, 0x7c, 0x35, 0x01, 0x02, 0x5a, 0x7c, 0x35}};
	sent_msg.signature = out_byte_array((const pb_bytes_array_t *)&example_signature);

	size_t sent_msg_len;
	CHECK(pb_get_encoded_size(&sent_msg_len, ts_crypto_SignHashOut_fields, &sent_msg));
	uint8_t *sent_msg_buf = (uint8_t*)malloc(sent_msg_len);
	CHECK(sent_msg_len > 0);
	CHECK(sent_msg_buf);

	pb_ostream_t ostream = pb_ostream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK(pb_encode(&ostream, ts_crypto_SignHashOut_fields, &sent_msg));
	CHECK_EQUAL(sent_msg_len, ostream.bytes_written);

	/* Receiver - deserialize and use values */
	PB_BYTES_ARRAY_T(10) recv_signature = {10, {0}};
	ts_crypto_SignHashOut recv_msg = ts_crypto_SignHashOut_init_default;
	recv_msg.signature = in_byte_array((pb_bytes_array_t *)&recv_signature);

	pb_istream_t istream = pb_istream_from_buffer(sent_msg_buf, sent_msg_len);
	CHECK_EQUAL(sent_msg_len, istream.bytes_left);
	CHECK(pb_decode(&istream, ts_crypto_SignHashOut_fields, &recv_msg));
	CHECK_EQUAL(0, istream.bytes_left);

	free(sent_msg_buf);

	CHECK_EQUAL(example_signature.size, recv_signature.size);
	CHECK(memcmp(example_signature.bytes, recv_signature.bytes, example_signature.size) == 0);

	if (print_info) {
		printf("Serialized result_asym_sign len: %ld\n", sent_msg_len);
	}
}
