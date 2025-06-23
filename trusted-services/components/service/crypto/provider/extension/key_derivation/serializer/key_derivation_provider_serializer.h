/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef KEY_DERIVATION_PROVIDER_SERIALIZER_H
#define KEY_DERIVATION_PROVIDER_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/backend/crypto_backend.h>
#include "components/rpc/common/endpoint/rpc_service_interface.h"

/* Provides a common interface for parameter serialization operations
 * for the key_derivation service provider.
 */
struct key_derivation_provider_serializer {

	/* Operation: key_derivation_setup */
	rpc_status_t (*deserialize_key_derivation_setup_req)(const struct rpc_buffer *req_buf,
		psa_algorithm_t *alg);

	rpc_status_t (*serialize_key_derivation_setup_resp)(struct rpc_buffer *resp_buf,
		uint32_t op_handle);

	/* Operation: key_derivation_get_capacity */
	rpc_status_t (*deserialize_key_derivation_get_capacity_req)(
		const struct rpc_buffer *req_buf, uint32_t *op_handle);

	rpc_status_t (*serialize_key_derivation_get_capacity_resp)(struct rpc_buffer *resp_buf,
		size_t capacity);

	/* Operation: key_derivation_set_capacity */
	rpc_status_t (*deserialize_key_derivation_set_capacity_req)(
		const struct rpc_buffer *req_buf, uint32_t *op_handle, size_t *capacity);

	/* Operation: key_derivation_input_bytes */
	rpc_status_t (*deserialize_key_derivation_input_bytes_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		psa_key_derivation_step_t *step,
		const uint8_t **data, size_t *data_len);

	/* Operation: key_derivation_input_key */
	rpc_status_t (*deserialize_key_derivation_input_key_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		psa_key_derivation_step_t *step,
		psa_key_id_t *key_id);

	/* Operation: key_derivation_output_bytes */
	rpc_status_t (*deserialize_key_derivation_output_bytes_req)(
		const struct rpc_buffer *req_buf, uint32_t *op_handle, size_t *output_len);

	rpc_status_t (*serialize_key_derivation_output_bytes_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *data, size_t data_len);

	/* Operation: key_derivation_output_key */
	rpc_status_t (*deserialize_key_derivation_output_key_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		psa_key_attributes_t *attributes);

	rpc_status_t (*serialize_key_derivation_output_key_resp)(struct rpc_buffer *resp_buf,
		psa_key_id_t key_id);

	/* Operation: key_derivation_abort */
	rpc_status_t (*deserialize_key_derivation_abort_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);

	/* Operation: key_derivation_key_agreement */
	rpc_status_t (*deserialize_key_derivation_key_agreement_req)(
		const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		psa_key_derivation_step_t *step,
		psa_key_id_t *private_key_id,
		const uint8_t **peer_key, size_t *peer_key_len);

	/* Operation: key_derivation_raw_key_agreement */
	rpc_status_t (*deserialize_key_derivation_raw_key_agreement_req)(
		const struct rpc_buffer *req_buf,
		psa_algorithm_t *alg,
		psa_key_id_t *private_key_id,
		const uint8_t **peer_key, size_t *peer_key_len);

	rpc_status_t (*serialize_key_derivation_raw_key_agreement_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *output, size_t output_len);
};

#endif /* KEY_DERIVATION_PROVIDER_SERIALIZER_H */
