/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <string.h>
#include <stdlib.h>
#include <common/tlv/tlv.h>
#include <service/crypto/backend/crypto_backend.h>
#include <protocols/service/crypto/packed-c/mac.h>
#include "packedc_mac_provider_serializer.h"

/* Operation: mac_setup */
static rpc_status_t deserialize_mac_setup_req(const struct rpc_buffer *req_buf,
	psa_key_id_t *key_id,
	psa_algorithm_t *alg)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_mac_setup_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_mac_setup_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*key_id = recv_msg.key_id;
		*alg = recv_msg.alg;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_mac_setup_resp(struct rpc_buffer *resp_buf,
	uint32_t op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_crypto_mac_setup_out resp_msg;
	size_t fixed_len = sizeof(struct ts_crypto_mac_setup_out);

	resp_msg.op_handle = op_handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: mac_update */
static rpc_status_t deserialize_mac_update_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **data, size_t *data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_mac_update_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_mac_update_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_MAC_UPDATE_IN_TAG_DATA, &decoded_record)) {

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

/* Operation: mac_finish */
static rpc_status_t deserialize_mac_sign_finish_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_mac_sign_finish_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_mac_sign_finish_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

static rpc_status_t serialize_mac_sign_finish_resp(struct rpc_buffer *resp_buf,
	const uint8_t *mac, size_t mac_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct tlv_iterator resp_iter;

	struct tlv_record out_record;
	out_record.tag = TS_CRYPTO_MAC_SIGN_FINISH_OUT_TAG_MAC;
	out_record.length = mac_len;
	out_record.value = mac;

	tlv_iterator_begin(&resp_iter, resp_buf->data, resp_buf->size);

	if (tlv_encode(&resp_iter, &out_record)) {

		resp_buf->data_length = tlv_required_space(mac_len);
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: mac_verify_finish */
static rpc_status_t deserialize_mac_verify_finish_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle,
	const uint8_t **mac, size_t *mac_len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_mac_verify_finish_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_mac_verify_finish_in);

	if (expected_fixed_len <= req_buf->data_length) {

		struct tlv_const_iterator req_iter;
		struct tlv_record decoded_record;

		rpc_status = RPC_SUCCESS;

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*op_handle = recv_msg.op_handle;

		tlv_const_iterator_begin(&req_iter,
			(uint8_t*)req_buf->data + expected_fixed_len,
			req_buf->data_length - expected_fixed_len);

		if (tlv_find_decode(&req_iter, TS_CRYPTO_MAC_SIGN_FINISH_OUT_TAG_MAC, &decoded_record)) {

			*mac = decoded_record.value;
			*mac_len = decoded_record.length;
		}
		else {
			/* Default to a zero length data */
			*mac_len = 0;
		}
	}

	return rpc_status;
}

/* Operation: mac_abort */
static rpc_status_t deserialize_mac_abort_req(const struct rpc_buffer *req_buf,
	uint32_t *op_handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_crypto_mac_abort_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_crypto_mac_abort_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*op_handle = recv_msg.op_handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Singleton method to provide access to the serializer instance */
const struct mac_provider_serializer *packedc_mac_provider_serializer_instance(void)
{
	static const struct mac_provider_serializer instance = {
		deserialize_mac_setup_req,
		serialize_mac_setup_resp,
		deserialize_mac_update_req,
		deserialize_mac_sign_finish_req,
		serialize_mac_sign_finish_resp,
		deserialize_mac_verify_finish_req,
		deserialize_mac_abort_req
	};

	return &instance;
}
