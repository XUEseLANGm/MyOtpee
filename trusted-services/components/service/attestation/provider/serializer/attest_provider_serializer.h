/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ATTEST_PROVIDER_SERIALIZER_H
#define ATTEST_PROVIDER_SERIALIZER_H

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include <stddef.h>
#include <stdint.h>

/* Provides a common interface for parameter serialization operations
 * for the attestation service provider.  Allows alternative serialization
 * protocols to be used without hard-wiring a particular protocol
 * into the service provider code.  A concrete serializer must
 * implement this interface.
 */
struct attest_provider_serializer {

	/* Operation: get_token */
	rpc_status_t (*deserialize_get_token_req)(const struct rpc_buffer *req_buf,
						  uint8_t *auth_challenge,
						  size_t *auth_challenge_len);

	rpc_status_t (*serialize_get_token_resp)(struct rpc_buffer *resp_buf, const uint8_t *token,
						 size_t token_size);

	/* Operation: get_token_size */
	rpc_status_t (*deserialize_get_token_size_req)(const struct rpc_buffer *req_buf,
						       size_t *auth_challenge_len);

	rpc_status_t (*serialize_get_token_size_resp)(struct rpc_buffer *resp_buf,
						      size_t token_size);

	/* Operation: export_iak_public_key */
	rpc_status_t (*serialize_export_iak_public_key_resp)(struct rpc_buffer *resp_buf,
							     const uint8_t *data, size_t data_len);

	/* Operation: import_iak */
	rpc_status_t (*deserialize_import_iak_req)(const struct rpc_buffer *req_buf, uint8_t *data,
						   size_t *data_len);
};

#endif /* ATTEST_PROVIDER_SERIALIZER_H */
