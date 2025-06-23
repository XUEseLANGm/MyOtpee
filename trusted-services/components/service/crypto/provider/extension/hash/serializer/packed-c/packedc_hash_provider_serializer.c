/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <string.h>
#include <stdlib.h>
#include <common/tlv/tlv.h>
#include <service/crypto/backend/crypto_backend.h>
#include <protocols/service/crypto/packed-c/hash.h>
#include "packedc_hash_provider_serializer.h"

/* Operation: hash_setup */
static rpc_status_t deserialize_hash_setup_req(const struct rpc_buffer *req_buf,
	psa_algorithm_t *alg)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_hash_setup_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_hash_setup_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*alg = recv_msg.alg;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_hash_setup_resp(struct rpc_buffer *resp_buf,
	uint32_t op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_hash_setup_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_hash_setup_out);

	resp_msg.op_handle = op_handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: hash_update */
static rpc_status_t deserialize_hash_update_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **data, size_t *data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_hash_update_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_hash_update_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_HASH_UPDATE_IN_TAG_DATA, &decoded_record)) {

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

/* Operation: hash_finish */
static rpc_status_t deserialize_hash_finish_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_hash_finish_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_hash_finish_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_hash_finish_resp(struct rpc_buffer *resp_buf,
	const uint8_t *hash, size_t hash_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_HASH_FINISH_OUT_TAG_HASH;
	out_record.length = hash_len;
	out_record.value = hash;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(hash_len);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: hash_abort */
static rpc_status_t deserialize_hash_abort_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_hash_abort_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_hash_abort_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: hash_verify */
static rpc_status_t deserialize_hash_verify_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **hash, size_t *hash_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_hash_verify_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_hash_verify_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_HASH_VERIFY_IN_TAG_HASH, &decoded_record)) {

			*hash = decoded_record.value;
			*hash_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*hash_len = 0;
		}
	}

	return rpc_status;
}

/* Operation: hash_clone */
static rpc_status_t deserialize_hash_clone_req(const struct rpc_buffer *req_buf,
	uint32_t *source_op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_hash_clone_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_hash_clone_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*source_op_handle = recv_msg.source_op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_hash_clone_resp(struct rpc_buffer *resp_buf,
	uint32_t target_op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_hash_clone_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_hash_clone_out);

	resp_msg.target_op_handle = target_op_handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Singleton method to provide access to the serializer instance */
const struct hash_provider_serializer *packedc_hash_provider_serializer_instance(void)
{
	static const struct hash_provider_serializer instance = {
		deserialize_hash_setup_req,
		serialize_hash_setup_resp,
		deserialize_hash_update_req,
		deserialize_hash_finish_req,
		serialize_hash_finish_resp,
		deserialize_hash_abort_req,
		deserialize_hash_verify_req,
		deserialize_hash_clone_req,
		serialize_hash_clone_resp
	};

	return &instance;
}
