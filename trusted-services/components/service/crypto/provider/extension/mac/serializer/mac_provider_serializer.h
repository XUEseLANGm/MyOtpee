/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MAC_PROVIDER_SERIALIZER_H
#define MAC_PROVIDER_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/backend/crypto_backend.h>
#include "components/rpc/common/endpoint/rpc_service_interface.h"

/* Provides a common interface for parameter serialization operations
 * for the mac service provider.
 */
struct mac_provider_serializer {

	/* Operation: mac_setup */
	rpc_status_t (*deserialize_mac_setup_req)(const struct rpc_buffer *req_buf,
		psa_key_id_t *key_id,
		psa_algorithm_t *alg);

	rpc_status_t (*serialize_mac_setup_resp)(struct rpc_buffer *resp_buf,
		uint32_t op_handle);

	/* Operation: mac_update */
	rpc_status_t (*deserialize_mac_update_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **data, size_t *data_len);

	/* Operation: mac_sign_finish */
	rpc_status_t (*deserialize_mac_sign_finish_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);

	rpc_status_t (*serialize_mac_sign_finish_resp)(struct rpc_buffer *resp_buf,
		const uint8_t *mac, size_t mac_len);

	/* Operation: mac_verify_finish */
	rpc_status_t (*deserialize_mac_verify_finish_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle,
		const uint8_t **mac, size_t *mac_len);

	/* Operation: mac_abort */
	rpc_status_t (*deserialize_mac_abort_req)(const struct rpc_buffer *req_buf,
		uint32_t *op_handle);
};

#endif /* MAC_PROVIDER_SERIALIZER_H */
