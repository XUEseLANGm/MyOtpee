/*
 * Copyright (c) 2020-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <protocols/rpc/common/packed-c/status.h>
#include "secure_storage_ipc.h"
#include <psa/client.h>
#include <psa/sid.h>
#include <rpc_caller.h>
#include <string.h>
#include <trace.h>


static psa_status_t secure_storage_ipc_set(void *context, uint32_t client_id,
			 psa_storage_uid_t uid, size_t data_length,
			 const void *p_data, psa_storage_create_flags_t create_flags)
{
	struct secure_storage_ipc *ipc = context;
	struct rpc_caller_interface *caller = ipc->client.session->caller;
	psa_status_t psa_status;
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&uid), .len = sizeof(uid) },
		{ .base = psa_ptr_const_to_u32(p_data), .len = data_length },
		{ .base = psa_ptr_to_u32(&create_flags), .len = sizeof(create_flags) },
	};

	ipc->client.rpc_status = TS_RPC_CALL_ACCEPTED;

	psa_status = psa_call_client_id(caller, ipc->service_handle, client_id,
					TFM_PS_ITS_SET, in_vec,
					IOVEC_LEN(in_vec), NULL, 0);
	if (psa_status < 0)
		EMSG("ipc_set: psa_call failed: %d", psa_status);

	return psa_status;
}

static psa_status_t secure_storage_ipc_get(void *context,
					   uint32_t client_id,
					   psa_storage_uid_t uid,
					   size_t data_offset,
					   size_t data_size,
					   void *p_data,
					   size_t *p_data_length)
{
	struct secure_storage_ipc *ipc = context;
	struct rpc_caller_interface *caller = ipc->client.session->caller;
	psa_status_t psa_status;
	uint32_t offset = (uint32_t)data_offset;
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&uid), .len = sizeof(uid) },
		{ .base = psa_ptr_to_u32(&offset), .len = sizeof(offset) },
	};
	struct psa_outvec out_vec[] = {
		{ .base = psa_ptr_to_u32(p_data), .len = data_size },
	};

	if (!p_data_length) {
		EMSG("ipc_get: p_data_length not defined");
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	psa_status = psa_call_client_id(caller, ipc->service_handle, client_id,
					TFM_PS_ITS_GET, in_vec,
					IOVEC_LEN(in_vec), out_vec,
					IOVEC_LEN(out_vec));
	if (psa_status == PSA_SUCCESS)
		*p_data_length = out_vec[0].len;

	return psa_status;
}

static psa_status_t secure_storage_ipc_get_info(void *context,
						uint32_t client_id,
						psa_storage_uid_t uid,
						struct psa_storage_info_t *p_info)
{
	struct secure_storage_ipc *ipc = context;
	struct rpc_caller_interface *caller = ipc->client.session->caller;
	psa_status_t psa_status;
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&uid), .len = sizeof(uid) },
	};
	struct psa_outvec out_vec[] = {
		{ .base = psa_ptr_to_u32(p_info), .len = sizeof(*p_info) },
	};

	psa_status = psa_call_client_id(caller, ipc->service_handle, client_id,
					TFM_PS_ITS_GET_INFO, in_vec,
					IOVEC_LEN(in_vec), out_vec,
					IOVEC_LEN(out_vec));
	if (psa_status != PSA_SUCCESS)
		EMSG("ipc_get_info: failed to psa_call: %d", psa_status);

	return psa_status;
}

static psa_status_t secure_storage_ipc_remove(void *context,
						uint32_t client_id,
						psa_storage_uid_t uid)
{
	struct secure_storage_ipc *ipc = context;
	struct rpc_caller_interface *caller = ipc->client.session->caller;
	psa_status_t psa_status;
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&uid), .len = sizeof(uid) },
	};

	psa_status = psa_call_client_id(caller, ipc->service_handle, client_id,
					TFM_PS_ITS_REMOVE, in_vec,
					IOVEC_LEN(in_vec), NULL, 0);
	if (psa_status != PSA_SUCCESS)
		EMSG("ipc_remove: failed to psa_call: %d", psa_status);

	return psa_status;
}

static psa_status_t secure_storage_ipc_create(void *context,
					      uint32_t client_id,
					      uint64_t uid,
					      size_t capacity,
					      uint32_t create_flags)
{
	(void)context;
	(void)uid;
	(void)client_id;
	(void)capacity;
	(void)create_flags;

	return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t secure_storage_set_extended(void *context,
						uint32_t client_id,
						uint64_t uid,
						size_t data_offset,
						size_t data_length,
						const void *p_data)
{
	(void)context;
	(void)uid;
	(void)client_id;
	(void)data_offset;
	(void)data_length;
	(void)p_data;

	return PSA_ERROR_NOT_SUPPORTED;
}

static uint32_t secure_storage_get_support(void *context, uint32_t client_id)
{
	struct secure_storage_ipc *ipc = context;
	struct rpc_caller_interface *caller = ipc->client.session->caller;
	psa_status_t psa_status;
	uint32_t support_flags;
	uint32_t dummy_vec = 0;
	/* Use dummy in vector to guarantee parameter checking */
	struct psa_invec in_vec[] = {
		{ .base = psa_ptr_to_u32(&dummy_vec), .len = sizeof(dummy_vec) },
	};

	struct psa_outvec out_vec[] = {
		{ .base = psa_ptr_to_u32(&support_flags), .len =  sizeof(support_flags) },
	};

	psa_status = psa_call_client_id(caller, ipc->service_handle, client_id,
					TFM_PS_ITS_GET_SUPPORT, in_vec, IOVEC_LEN(in_vec),
					out_vec, IOVEC_LEN(out_vec));
	if (psa_status != PSA_SUCCESS)
		EMSG("ipc_get_support: failed to psa_call: %d", psa_status);

	return psa_status;
}

struct storage_backend *secure_storage_ipc_init(struct secure_storage_ipc *context,
						struct rpc_caller_session *session)
{
	service_client_init(&context->client, session);

	static const struct storage_backend_interface interface =
	{
		.set = secure_storage_ipc_set,
		.get = secure_storage_ipc_get,
		.get_info = secure_storage_ipc_get_info,
		.remove = secure_storage_ipc_remove,
		.create = secure_storage_ipc_create,
		.set_extended = secure_storage_set_extended,
		.get_support = secure_storage_get_support,
	};

	context->backend.context = context;
	context->backend.interface = &interface;

	return &context->backend;
}

void secure_storage_ipc_deinit(struct secure_storage_ipc *context)
{
	service_client_deinit(&context->client);
}
