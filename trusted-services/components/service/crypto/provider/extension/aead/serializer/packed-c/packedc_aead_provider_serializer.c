/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <string.h>
#include <stdlib.h>
#include <common/tlv/tlv.h>
#include <service/crypto/backend/crypto_backend.h>
#include <protocols/service/crypto/packed-c/aead.h>
#include "packedc_aead_provider_serializer.h"

/* Operation: aead_setup */
static rpc_status_t deserialize_aead_setup_req(const struct rpc_buffer *req_buf,
	psa_key_id_t *id,
	psa_algorithm_t *alg)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_setup_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_setup_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*id = recv_msg.key_id;
		*alg = recv_msg.alg;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_aead_setup_resp(struct rpc_buffer *resp_buf,
	uint32_t op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_aead_setup_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_aead_setup_out);

	resp_msg.op_handle = op_handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: aead_generate_nonce */
static rpc_status_t deserialize_aead_generate_nonce_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_generate_nonce_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_generate_nonce_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_aead_generate_nonce_resp(struct rpc_buffer *resp_buf,
	const uint8_t *nonce, size_t nonce_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_AEAD_GENERATE_NONCE_OUT_TAG_NONCE;
	out_record.length = nonce_len;
	out_record.value = nonce;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(out_record.length);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: aead_set_nonce */
static rpc_status_t deserialize_aead_set_nonce_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **nonce, size_t *nonce_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_set_nonce_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_set_nonce_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_AEAD_SET_NONCE_IN_TAG_NONCE, &decoded_record)) {

			*nonce = decoded_record.value;
			*nonce_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*nonce_len = 0;
		}
	}

	return rpc_status;
}

/* Operation: aead_set_lengths */
static rpc_status_t deserialize_aead_set_lengths_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	size_t *ad_length,
	size_t *plaintext_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_set_lengths_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_set_lengths_in);

	if (expected_fixed_len <= req_buf->data_length) {

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;
		*ad_length = recv_msg.ad_length;
		*plaintext_length = recv_msg.plaintext_length;
	}

	return rpc_status;
}

/* Operation: aead_update_ad */
static rpc_status_t deserialize_aead_update_ad_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **input, size_t *input_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_update_ad_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_update_ad_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_AEAD_UPDATE_AD_IN_TAG_DATA, &decoded_record)) {

			*input = decoded_record.value;
			*input_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*input_len = 0;
		}
	}

	return rpc_status;
}

/* Operation: aead_update */
static rpc_status_t deserialize_aead_update_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **input, size_t *input_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_update_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_update_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_AEAD_UPDATE_IN_TAG_DATA, &decoded_record)) {

			*input = decoded_record.value;
			*input_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*input_len = 0;
		}
	}

	return rpc_status;
}

static rpc_status_t serialize_aead_update_resp(struct rpc_buffer *resp_buf,
	const uint8_t *output, size_t output_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_AEAD_UPDATE_OUT_TAG_DATA;
	out_record.length = output_len;
	out_record.value = output;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(out_record.length);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: aead_finish */
static rpc_status_t deserialize_aead_finish_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_finish_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_finish_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_aead_finish_resp(struct rpc_buffer *resp_buf,
	const uint8_t *aeadtext, size_t aeadtext_len,
	const uint8_t *tag, size_t tag_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;
	int encoded_tlv_count = 0;

	resp_buf->data_length = 0;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_AEAD_FINISH_OUT_TAG_CIPHERTEXT;
	out_record.length = aeadtext_len;
	out_record.value = aeadtext;

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length += tlv_required_space(out_record.length);
		++encoded_tlv_count;
	}

	out_record.tag = TS_CRYPTO_AEAD_FINISH_OUT_TAG_TAG;
	out_record.length = tag_len;
	out_record.value = tag;

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length += tlv_required_space(out_record.length);
		++encoded_tlv_count;
	}

	/* Check that expected TLV records have been encoded */
	if (encoded_tlv_count == 2)
		rpc_status = RPC_SUCCESS;

	return rpc_status;
}

/* Operation: aead_verify */
static rpc_status_t deserialize_aead_verify_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **tag, size_t *tag_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_verify_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_verify_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_AEAD_VERIFY_IN_TAG_TAG, &decoded_record)) {

			*tag = decoded_record.value;
			*tag_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*tag_len = 0;
		}
	}

	return rpc_status;
}

static rpc_status_t serialize_aead_verify_resp(struct rpc_buffer *resp_buf,
	const uint8_t *plaintext, size_t plaintext_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_AEAD_VERIFY_OUT_TAG_PLAINTEXT;
	out_record.length = plaintext_len;
	out_record.value = plaintext;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(out_record.length);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: aead_abort */
static rpc_status_t deserialize_aead_abort_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_aead_abort_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_aead_abort_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Singleton method to provide access to the serializer instance */
const struct aead_provider_serializer *packedc_aead_provider_serializer_instance(void)
{
	static const struct aead_provider_serializer instance = {
		deserialize_aead_setup_req,
		serialize_aead_setup_resp,
		deserialize_aead_generate_nonce_req,
		serialize_aead_generate_nonce_resp,
		deserialize_aead_set_nonce_req,
		deserialize_aead_set_lengths_req,
		deserialize_aead_update_ad_req,
		deserialize_aead_update_req,
		serialize_aead_update_resp,
		deserialize_aead_finish_req,
		serialize_aead_finish_resp,
		deserialize_aead_verify_req,
		serialize_aead_verify_resp,
		deserialize_aead_abort_req
	};

	return &instance;
}
