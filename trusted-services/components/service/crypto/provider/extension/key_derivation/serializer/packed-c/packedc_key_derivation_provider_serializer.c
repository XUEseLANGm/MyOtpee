/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <string.h>
#include <stdlib.h>
#include <common/tlv/tlv.h>
#include <service/crypto/backend/crypto_backend.h>
#include <protocols/service/crypto/packed-c/key_derivation.h>
#include <service/crypto/provider/serializer/packed-c/packedc_key_attributes_translator.h>
#include "packedc_key_derivation_provider_serializer.h"

/* Operation: key_derivation_setup */
static rpc_status_t deserialize_key_derivation_setup_req(
	const struct rpc_buffer *req_buf,
	psa_algorithm_t *alg)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_setup_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_setup_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*alg = recv_msg.alg;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_key_derivation_setup_resp(
	struct rpc_buffer *resp_buf,
	uint32_t op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_key_derivation_setup_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_key_derivation_setup_out);

	resp_msg.op_handle = op_handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_get_capacity */
static rpc_status_t deserialize_key_derivation_get_capacity_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_get_capacity_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_get_capacity_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_key_derivation_get_capacity_resp(
	struct rpc_buffer *resp_buf,
	size_t capacity)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_key_derivation_get_capacity_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_key_derivation_get_capacity_out);

	resp_msg.capacity = capacity;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_set_capacity */
static rpc_status_t deserialize_key_derivation_set_capacity_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	size_t *capacity)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_set_capacity_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_set_capacity_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		*capacity = recv_msg.capacity;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_input_bytes */
static rpc_status_t deserialize_key_derivation_input_bytes_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	psa_key_derivation_step_t *step,
	const uint8_t **data, size_t *data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_input_bytes_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_input_bytes_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;
		*step = recv_msg.step;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter,
			TS_CRYPTO_KEY_DERIVATION_INPUT_BYTES_IN_TAG_DATA, &decoded_record)) {

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

/* Operation: key_derivation_input_key */
static rpc_status_t deserialize_key_derivation_input_key_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	psa_key_derivation_step_t *step,
	psa_key_id_t *key_id)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_input_key_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_input_key_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		*step = recv_msg.step;
		*key_id = recv_msg.key_id;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_output_bytes */
static rpc_status_t deserialize_key_derivation_output_bytes_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	size_t *output_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_output_bytes_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_output_bytes_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		*output_len = recv_msg.output_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_key_derivation_output_bytes_resp(
	struct rpc_buffer *resp_buf,
	const uint8_t *data, size_t data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_KEY_DERIVATION_OUTPUT_BYTES_OUT_TAG_DATA;
	out_record.length = data_length;
	out_record.value = data;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(data_length);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_output_key */
static rpc_status_t deserialize_key_derivation_output_key_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	psa_key_attributes_t *attributes)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_output_key_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_output_key_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;
		packedc_crypto_provider_translate_key_attributes_from_proto(attributes,
			&recv_msg.attributes);

		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_key_derivation_output_key_resp(
	struct rpc_buffer *resp_buf,
	psa_key_id_t key_id)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_key_derivation_output_key_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_key_derivation_output_key_out);

	resp_msg.key_id = key_id;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_abort */
static rpc_status_t deserialize_key_derivation_abort_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_abort_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_abort_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: key_derivation_key_agreement */
static rpc_status_t deserialize_key_derivation_key_agreement_req(
	const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	psa_key_derivation_step_t *step,
	psa_key_id_t *private_key_id,
	const uint8_t **peer_key, size_t *peer_key_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_key_derivation_key_agreement_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_key_derivation_key_agreement_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;
		*step = recv_msg.step;
		*private_key_id = recv_msg.private_key_id;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter,
			TS_CRYPTO_KEY_DERIVATION_KEY_AGREEMENT_IN_TAG_PEER_KEY, &decoded_record)) {

			*peer_key = decoded_record.value;
			*peer_key_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*peer_key_len = 0;
		}
	}

	return rpc_status;
}

/* Operation: key_derivation_raw_key_agreement */
static rpc_status_t deserialize_key_derivation_raw_key_agreement_req(
	const struct rpc_buffer *req_buf,
	psa_algorithm_t *alg,
	psa_key_id_t *private_key_id,
	const uint8_t **peer_key, size_t *peer_key_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_raw_key_agreement_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_raw_key_agreement_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*alg = recv_msg.alg;
		*private_key_id = recv_msg.private_key_id;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter,
			TS_CRYPTO_RAW_KEY_AGREEMENT_IN_TAG_PEER_KEY, &decoded_record)) {

			*peer_key = decoded_record.value;
			*peer_key_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*peer_key_len = 0;
		}
	}

	return rpc_status;
}

static rpc_status_t serialize_key_derivation_raw_key_agreement_resp(
	struct rpc_buffer *resp_buf,
	const uint8_t *output, size_t output_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_RAW_KEY_AGREEMENT_OUT_TAG_OUTPUT;
	out_record.length = output_len;
	out_record.value = output;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(output_len);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Singleton method to provide access to the serializer instance */
const struct key_derivation_provider_serializer
	*packedc_key_derivation_provider_serializer_instance(void)
{
	static const struct key_derivation_provider_serializer instance = {
		deserialize_key_derivation_setup_req,
		serialize_key_derivation_setup_resp,
		deserialize_key_derivation_get_capacity_req,
		serialize_key_derivation_get_capacity_resp,
		deserialize_key_derivation_set_capacity_req,
		deserialize_key_derivation_input_bytes_req,
		deserialize_key_derivation_input_key_req,
		deserialize_key_derivation_output_bytes_req,
		serialize_key_derivation_output_bytes_resp,
		deserialize_key_derivation_output_key_req,
		serialize_key_derivation_output_key_resp,
		deserialize_key_derivation_abort_req,
		deserialize_key_derivation_key_agreement_req,
		deserialize_key_derivation_raw_key_agreement_req,
		serialize_key_derivation_raw_key_agreement_resp
	};

	return &instance;
}
