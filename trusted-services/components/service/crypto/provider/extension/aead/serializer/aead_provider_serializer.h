/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef AEAD_PROVIDER_SERIALIZER_H
#define AEAD_PROVIDER_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/backend/crypto_backend.h>
#include "components/rpc/common/endpoint/rpc_service_interface.h"

/* Provides a common interface for parameter serialization operations
 * for the aead service provider.
 */
struct aead_provider_serializer {

	/* Operation: aead_setup */
	rpc_status_t (*deserialize_aead_setup_req)(const struct rpc_buffer *req_buf,
		psa_key_id_t *id,
		psa_algorithm_t *alg);

	rpc_status_t (*serialize_aead_setup_resp)(struct rpc_buffer *resp_buf,
		uint32_t op_handle);

	/* Operation: aead_generate_nonce */
	rpc_status_t (*deserialize_aead_generate_nonce_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);

	rpc_status_t (*serialize_aead_generate_nonce_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *nonce, size_t nonce_len);

	/* Operation: aead_set_nonce */
	rpc_status_t (*deserialize_aead_set_nonce_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **nonce, size_t *nonce_len);

	/* Operation: aead_set_lengths */
	rpc_status_t (*deserialize_aead_set_lengths_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		size_t *ad_length,
		size_t *plaintext_length);

	/* Operation: aead_update_ad */
	rpc_status_t (*deserialize_aead_update_ad_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **input, size_t *input_len);

	/* Operation: aead_update */
	rpc_status_t (*deserialize_aead_update_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **input, size_t *input_len);

	rpc_status_t (*serialize_aead_update_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *output, size_t output_len);

	/* Operation: aead_finish */
	rpc_status_t (*deserialize_aead_finish_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);

	rpc_status_t (*serialize_aead_finish_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *aeadtext, size_t aeadtext_len,
		const uint8_t *tag, size_t tag_len);

	/* Operation: aead_verify */
	rpc_status_t (*deserialize_aead_verify_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **tag, size_t *tag_len);

	rpc_status_t (*serialize_aead_verify_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *plaintext, size_t plaintext_len);

	/* Operation: aead_abort */
	rpc_status_t (*deserialize_aead_abort_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);
};

#endif /* AEAD_PROVIDER_SERIALIZER_H */
