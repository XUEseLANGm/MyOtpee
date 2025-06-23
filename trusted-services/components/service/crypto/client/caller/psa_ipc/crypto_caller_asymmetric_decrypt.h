/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_IPC_CRYPTO_CALLER_ASYMMETRIC_DECRYPT_H
#define PSA_IPC_CRYPTO_CALLER_ASYMMETRIC_DECRYPT_H

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

static inline psa_status_t crypto_caller_asymmetric_decrypt(
				    struct service_client *context,
				    psa_key_id_t id,
				    psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    const uint8_t *salt, size_t salt_length,
				    uint8_t *output, size_t output_size,
				    size_t *output_length)
{
	struct service_client *ipc = context;
	struct rpc_caller_interface *caller = ipc->session->caller;
	psa_status_t status;
	size_t in_len;
	struct psa_ipc_crypto_pack_iovec iov = {
		.function_id = TFM_CRYPTO_ASYMMETRIC_DECRYPT_SID,
		.key_id = id,
		.alg = alg,
	};

	/* Sanitize optional input */
	if (!salt && salt_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&iov), .len = iov_size },
		{ .base = psa_ptr_const_to_u32(input), .len = input_length },
		{ .base = psa_ptr_const_to_u32(salt), .len = salt_length },
	};
	struct psa_outvec out_vec[] = {
		{ .base = psa_ptr_to_u32(output), .len = output_size },
	};


	in_len = IOVEC_LEN(in_vec);
	if (!salt)
		in_len--;

	status = psa_call(caller, TFM_CRYPTO_HANDLE, PSA_IPC_CALL, in_vec,
			  in_len, out_vec, IOVEC_LEN(out_vec));

	*output_length = out_vec[0].len;

	return status;
}

#ifdef __cplusplus
}
#endif

#endif /* PSA_IPC_CRYPTO_CALLER_ASYMMETRIC_DECRYPT_H */
