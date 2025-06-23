/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_IPC_CRYPTO_CALLER_VERIFY_HASH_H
#define PSA_IPC_CRYPTO_CALLER_VERIFY_HASH_H

#include <string.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/client.h>
#include <psa/sid.h>
#include <service/common/client/service_client.h>
#include <service/crypto/backend/psa_ipc/crypto_ipc_backend.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/crypto/packed-c/opcodes.h>
#include <protocols/service/crypto/packed-c/key_attributes.h>
#include <protocols/service/crypto/packed-c/import_key.h>
#include "crypto_caller_key_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline psa_status_t crypto_caller_common(struct service_client *context,
						     psa_key_id_t id,
						     psa_algorithm_t alg,
						     const uint8_t *hash,
						     size_t hash_length,
						     const uint8_t *signature,
						     size_t signature_length,
						     uint32_t function_id)
{
	struct service_client *ipc = context;
	struct rpc_caller_interface *caller = ipc->session->caller;
	psa_status_t status;
	struct psa_ipc_crypto_pack_iovec iov = {
		.function_id = function_id,
		.key_id = id,
		.alg = alg,
	};
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&iov), .len = sizeof(struct psa_ipc_crypto_pack_iovec) },
		{ .base = psa_ptr_const_to_u32(hash), .len = hash_length },
		{ .base = psa_ptr_const_to_u32(signature), .len = signature_length},
	};

	status = psa_call(caller, TFM_CRYPTO_HANDLE, PSA_IPC_CALL, in_vec,
			  IOVEC_LEN(in_vec), NULL, 0);

	return status;
}

static inline psa_status_t crypto_caller_verify_hash(struct service_client *context,
						     psa_key_id_t id,
						     psa_algorithm_t alg,
						     const uint8_t *hash,
						     size_t hash_length,
						     const uint8_t *signature,
						     size_t signature_length)
{

	return crypto_caller_common(context,id,alg,hash,hash_length,
			signature,signature_length, TFM_CRYPTO_ASYMMETRIC_VERIFY_HASH_SID);
}

static inline psa_status_t crypto_caller_verify_message(struct service_client *context,
						     psa_key_id_t id,
						     psa_algorithm_t alg,
						     const uint8_t *hash,
						     size_t hash_length,
						     const uint8_t *signature,
						     size_t signature_length)
{

	return crypto_caller_common(context,id,alg,hash,hash_length,
			signature,signature_length, TFM_CRYPTO_ASYMMETRIC_VERIFY_MESSAGE_SID);
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_IPC_CRYPTO_CALLER_VERIFY_HASH_H */
