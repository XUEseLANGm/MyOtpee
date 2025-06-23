/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <string.h>
#include <stdlib.h>
#include <common/tlv/tlv.h>
#include <service/crypto/backend/crypto_backend.h>
#include <protocols/service/crypto/packed-c/cipher.h>
#include "packedc_cipher_provider_serializer.h"

/* Operation: cipher_setup */
static rpc_status_t deserialize_cipher_setup_req(const struct rpc_buffer *req_buf,
	psa_key_id_t *id,
	psa_algorithm_t *alg)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_cipher_setup_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_cipher_setup_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*id = recv_msg.key_id;
		*alg = recv_msg.alg;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_cipher_setup_resp(struct rpc_buffer *resp_buf,
	uint32_t op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_cipher_setup_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_cipher_setup_out);

	resp_msg.op_handle = op_handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: cipher_generate_iv */
static rpc_status_t deserialize_cipher_generate_iv_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_cipher_generate_iv_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_cipher_generate_iv_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_cipher_generate_iv_resp(struct rpc_buffer *resp_buf,
	const uint8_t *iv, size_t iv_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_CIPHER_GENERATE_IV_OUT_TAG_IV;
	out_record.length = iv_len;
	out_record.value = iv;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(iv_len);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: cipher_set_iv */
static rpc_status_t deserialize_cipher_set_iv_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **iv, size_t *iv_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_cipher_set_iv_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_cipher_set_iv_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_CIPHER_SET_IV_IN_TAG_IV, &decoded_record)) {

			*iv = decoded_record.value;
			*iv_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*iv_len = 0;
		}
	}

	return rpc_status;
}

/* Operation: cipher_update */
static rpc_status_t deserialize_cipher_update_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **data, size_t *data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_cipher_update_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_cipher_update_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_CIPHER_UPDATE_IN_TAG_DATA, &decoded_record)) {

			*data = decoded_record.value;
			*data_length = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*data_length = 0;
		}
	}

	return rpc_status;
}

static rpc_status_t serialize_cipher_update_resp(struct rpc_buffer *resp_buf,
		const uint8_t *data, size_t data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_CIPHER_UPDATE_OUT_TAG_DATA;
	out_record.length = data_length;
	out_record.value = data;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(data_length);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: cipher_finish */
static rpc_status_t deserialize_cipher_finish_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_cipher_finish_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_cipher_finish_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_cipher_finish_resp(struct rpc_buffer *resp_buf,
	const uint8_t *data, size_t data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_CIPHER_FINISH_OUT_TAG_DATA;
	out_record.length = data_length;
	out_record.value = data;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(data_length);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: cipher_abort */
static rpc_status_t deserialize_cipher_abort_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_cipher_abort_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_cipher_abort_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Singleton method to provide access to the serializer instance */
const struct cipher_provider_serializer *packedc_cipher_provider_serializer_instance(void)
{
	static const struct cipher_provider_serializer instance = {
		deserialize_cipher_setup_req,
		serialize_cipher_setup_resp,
		deserialize_cipher_generate_iv_req,
		serialize_cipher_generate_iv_resp,
		deserialize_cipher_set_iv_req,
		deserialize_cipher_update_req,
		serialize_cipher_update_resp,
		deserialize_cipher_finish_req,
		serialize_cipher_finish_resp,
		deserialize_cipher_abort_req
	};

	return &instance;
}
