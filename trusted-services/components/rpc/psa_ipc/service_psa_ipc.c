/*
 * Copyright (c) 2021-2024, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

#include <protocols/rpc/common/packed-c/status.h>
#include <psa/error.h>
#include <rpc_caller.h>

#include <psa/client.h>
#include <psa_ipc_caller.h>
#include "service_psa_ipc_openamp_lib.h"

static inline void *unaligned_memcpy(void *dst_init, const void *src_init,
				     size_t len)
{
	char *dst = dst_init;
	const char *src = src_init;

	while (len--)
		*dst++ = *src++;

	return dst_init;
}

static struct psa_invec *psa_call_in_vec_param(uint8_t *req)
{
	return (struct psa_invec *)(req + sizeof(struct ns_openamp_msg));
}

static struct psa_outvec *psa_call_out_vec_param(uint8_t *req, size_t in_len)
{
	return (struct psa_outvec *)(req + sizeof(struct ns_openamp_msg) +
				     (in_len * sizeof(struct psa_invec)));
}

static size_t psa_call_header_len(const struct psa_invec *in_vec, size_t in_len,
				  struct psa_outvec *out_vec, size_t out_len)
{
	return sizeof(struct ns_openamp_msg) + (in_len * sizeof(*in_vec)) +
		(out_len * sizeof(*out_vec));
}

static size_t psa_call_in_vec_len(const struct psa_invec *in_vec, size_t in_len)
{
	size_t req_len = 0;
	int i = 0;

	if (!in_vec || !in_len)
		return 0;

	for (i = 0; i < in_len; i++)
		req_len += in_vec[i].len;

	return req_len;
}

static uint32_t psa_virt_to_phys_u32(struct rpc_caller_interface *caller, void *va)
{
	return (uintptr_t)psa_ipc_virt_to_phys(caller->context, va);
}

psa_handle_t psa_connect(struct rpc_caller_interface *caller, uint32_t sid,
			 uint32_t version)
{
	struct s_openamp_msg *resp_msg;
	struct ns_openamp_msg *req_msg;
	psa_ipc_call_handle rpc_handle;
	size_t resp_len;
	uint8_t *resp;
	uint8_t *req;
	int ret;

	rpc_handle = psa_ipc_caller_begin(caller, &req, sizeof(struct ns_openamp_msg));
	if (!rpc_handle) {
		EMSG("psa_connect: could not get rpc handle");
		return PSA_ERROR_GENERIC_ERROR;
	}

	req_msg = (struct ns_openamp_msg *)req;

	req_msg->call_type = OPENAMP_PSA_CONNECT;
	req_msg->params.psa_connect_params.sid = sid;
	req_msg->params.psa_connect_params.version = version;

	ret = psa_ipc_caller_invoke(rpc_handle, 0, &resp, &resp_len);
	if (ret != RPC_SUCCESS) {
		EMSG("invoke failed: %d", ret);
		return PSA_NULL_HANDLE;
	}

	resp_msg = (struct s_openamp_msg *)resp;

	psa_ipc_caller_end(rpc_handle);

	return resp_msg ? (psa_handle_t)resp_msg->reply : PSA_NULL_HANDLE;
}

static psa_status_t __psa_call(struct rpc_caller_interface *caller, psa_handle_t psa_handle,
			       int32_t client_id, int32_t type,
			       const struct psa_invec *in_vec, size_t in_len,
			       struct psa_outvec *out_vec, size_t out_len)
{
	struct s_openamp_msg *resp_msg = NULL;
	struct psa_outvec *out_vec_param;
	struct psa_invec *in_vec_param;
	struct ns_openamp_msg *req_msg;
	psa_ipc_call_handle rpc_handle;
	size_t in_vec_len;
	size_t header_len;
	uint8_t *payload;
	size_t resp_len;
	uint8_t *resp;
	uint8_t *req;
	int ret;
	int i;

	if ((psa_handle == PSA_NULL_HANDLE) || !caller)
		return PSA_ERROR_INVALID_ARGUMENT;

	header_len = psa_call_header_len(in_vec, in_len, out_vec, out_len);
	in_vec_len = psa_call_in_vec_len(in_vec, in_len);

	rpc_handle = psa_ipc_caller_begin(caller, &req, header_len + in_vec_len);
	if (!rpc_handle) {
		EMSG("psa_call: could not get handle");
		return PSA_ERROR_GENERIC_ERROR;
	}

	payload = req + header_len;

	out_vec_param = psa_call_out_vec_param(req, in_len);
	in_vec_param = psa_call_in_vec_param(req);

	req_msg = (struct ns_openamp_msg *)req;

	req_msg->call_type = OPENAMP_PSA_CALL;
	req_msg->request_id = 1234;
	req_msg->client_id = client_id;
	req_msg->params.psa_call_params.handle = psa_handle;
	req_msg->params.psa_call_params.type = type;
	req_msg->params.psa_call_params.in_len = in_len;
	req_msg->params.psa_call_params.in_vec = psa_virt_to_phys_u32(caller, in_vec_param);
	req_msg->params.psa_call_params.out_len = out_len;
	req_msg->params.psa_call_params.out_vec = psa_virt_to_phys_u32(caller, out_vec_param);

	for (i = 0; i < in_len; i++) {
		in_vec_param[i].base = psa_virt_to_phys_u32(caller, payload);
		in_vec_param[i].len = in_vec[i].len;

		unaligned_memcpy(payload, psa_u32_to_ptr(in_vec[i].base),
				 in_vec[i].len);
		payload += in_vec[i].len;
	}

	for (i = 0; i < out_len; i++) {
		out_vec_param[i].base = 0;
		out_vec_param[i].len = out_vec[i].len;
	}

	ret = psa_ipc_caller_invoke(rpc_handle, 0, &resp, &resp_len);
	if (ret != RPC_SUCCESS) {
		EMSG("psa_call: invoke failed: %d", ret);
		return PSA_ERROR_GENERIC_ERROR;
	}

	resp_msg = (struct s_openamp_msg *)resp;

	if (!resp_msg || !out_len || resp_msg->reply != PSA_SUCCESS)
		goto caller_end;

	out_vec_param = (struct psa_outvec *)psa_ipc_phys_to_virt(caller->context,
				psa_u32_to_ptr(resp_msg->params.out_vec));

	for (i = 0; i < resp_msg->params.out_len; i++) {
		out_vec[i].len = out_vec_param[i].len;
		unaligned_memcpy(psa_u32_to_ptr(out_vec[i].base),
				 psa_ipc_phys_to_virt(caller->context,
				      psa_u32_to_ptr(out_vec_param[i].base)),
				 out_vec[i].len);
	}

caller_end:
	psa_ipc_caller_end(rpc_handle);

	return resp_msg ? resp_msg->reply : PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_call_client_id(struct rpc_caller_interface *caller,
				psa_handle_t psa_handle, int32_t client_id,
				int32_t type, const struct psa_invec *in_vec,
				size_t in_len, struct psa_outvec *out_vec,
				size_t out_len)
{
	return __psa_call(caller, psa_handle, client_id, type, in_vec, in_len,
			  out_vec, out_len);
}

psa_status_t psa_call(struct rpc_caller_interface *caller, psa_handle_t psa_handle,
		      int32_t type, const struct psa_invec *in_vec,
		      size_t in_len, struct psa_outvec *out_vec, size_t out_len)
{
	return __psa_call(caller, psa_handle, 0, type, in_vec, in_len, out_vec,
			  out_len);
}

void psa_close(struct rpc_caller_interface *caller, psa_handle_t psa_handle)
{
	struct ns_openamp_msg *req_msg;
	psa_ipc_call_handle rpc_handle;
	size_t resp_len;
	uint8_t *resp;
	uint8_t *req;
	int ret;

	if ((psa_handle == PSA_NULL_HANDLE) || !caller)
		return;

	rpc_handle = psa_ipc_caller_begin(caller, &req, sizeof(struct ns_openamp_msg));
	if (!rpc_handle) {
		EMSG("psa_close: could not get handle");
		return;
	}

	req_msg = (struct ns_openamp_msg *)req;

	req_msg->call_type = OPENAMP_PSA_CLOSE;
	req_msg->params.psa_close_params.handle = psa_handle;

	ret = psa_ipc_caller_invoke(rpc_handle, 0, &resp, &resp_len);
	if (ret != TS_RPC_CALL_ACCEPTED) {
		EMSG("psa_close: invoke failed: %d", ret);
		return;
	}

	psa_ipc_caller_end(rpc_handle);
}
