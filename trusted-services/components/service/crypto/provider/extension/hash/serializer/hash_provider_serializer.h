/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HASH_PROVIDER_SERIALIZER_H
#define HASH_PROVIDER_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/backend/crypto_backend.h>
#include "components/rpc/common/endpoint/rpc_service_interface.h"

/* Provides a common interface for parameter serialization operations
 * for the hash service provider.
 */
struct hash_provider_serializer {

	/* Operation: hash_setup */
	rpc_status_t (*deserialize_hash_setup_req)(const struct rpc_buffer *req_buf,
		psa_algorithm_t *alg);

	rpc_status_t (*serialize_hash_setup_resp)(struct rpc_buffer *resp_buf,
		uint32_t op_handle);

	/* Operation: hash_update */
	rpc_status_t (*deserialize_hash_update_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **data, size_t *data_len);

	/* Operation: hash_finish */
	rpc_status_t (*deserialize_hash_finish_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);

	rpc_status_t (*serialize_hash_finish_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *hash, size_t hash_len);

	/* Operation: hash_abort */
	rpc_status_t (*deserialize_hash_abort_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);

	/* Operation: hash_verify */
	rpc_status_t (*deserialize_hash_verify_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **hash, size_t *hash_len);

	/* Operation: hash_clone */
	rpc_status_t (*deserialize_hash_clone_req)(const struct rpc_buffer *req_buf,
		uint32_t *source_op_handle);

	rpc_status_t (*serialize_hash_clone_resp)(struct rpc_buffer *resp_buf,
		uint32_t target_op_handle);
};

#endif /* HASH_PROVIDER_SERIALIZER_H */
