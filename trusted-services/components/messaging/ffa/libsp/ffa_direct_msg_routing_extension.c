// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 */

#include "ffa_direct_msg_routing_extension.h"
#include "ffa_api.h"
#include <stdbool.h>

#define SP_ID_INVALID FFA_ID_GET_ID_MASK
#define FFA_ROUTING_EXT_RC_BIT		BIT32(31)
#define FFA_ROUTING_EXT_ERROR_BIT	BIT32(30)
#define FFA_ROUTING_EXT_BITS_MASK	(FFA_ROUTING_EXT_RC_BIT | FFA_ROUTING_EXT_ERROR_BIT)

enum sp_rc_state { idle = 0, root, leaf, rc_root, internal, forwarding };

enum sp_rc_state state = idle;
static uint16_t own_id = SP_ID_INVALID;
static uint16_t caller_id = SP_ID_INVALID;
static uint16_t callee_id = SP_ID_INVALID;

static bool is_rc_message(const struct ffa_direct_msg *msg)
{
	return msg->args.args32[0] & FFA_ROUTING_EXT_RC_BIT;
}

static bool is_error_message(const struct ffa_direct_msg *msg)
{
	return msg->args.args32[0] & FFA_ROUTING_EXT_ERROR_BIT;
}

static ffa_result get_error_code_from_message(const struct ffa_direct_msg *msg)
{
	return (ffa_result)msg->args.args32[1];
}

static ffa_result send_rc_error_message(struct ffa_direct_msg *req,
					ffa_result error_code)
{
	return ffa_msg_send_direct_resp_32(req->destination_id, req->source_id,
					(FFA_ROUTING_EXT_ERROR_BIT |
					 FFA_ROUTING_EXT_RC_BIT),
					error_code, 0, 0, 0, req);
}

static ffa_result send_rc_error_message_to_rc_root(struct ffa_direct_msg *resp,
						   ffa_result error_code)
{
	return ffa_msg_send_direct_req_32(own_id, callee_id,
				       (FFA_ROUTING_EXT_RC_BIT |
					FFA_ROUTING_EXT_ERROR_BIT),
				       error_code, 0, 0, 0, resp);
}

static ffa_result deny_unexpected_rc_responses(struct ffa_direct_msg *req)
{
	ffa_result ffa_res = FFA_OK;

	while (is_rc_message(req)) {
		ffa_res = send_rc_error_message(req, FFA_DENIED);
		if (ffa_res != FFA_OK)
			return ffa_res;
	}

	return FFA_OK;
}

static ffa_result deny_unexpected_requests(struct ffa_direct_msg *req)
{
	ffa_result ffa_res = FFA_OK;

	while (!is_rc_message(req) || req->source_id != caller_id) {
		ffa_res = send_rc_error_message(req, FFA_BUSY);
		if (ffa_res != FFA_OK) {
			/* Sending error message as a response to an invalid
			 * request has failed. Sending and FFA_MSG_WAIT to have
			 * a chance for receiving a valid message.
			 */
			ffa_res = ffa_msg_wait(req);
			if (ffa_res != FFA_OK) {
				/* Even the FFA_MSG_WAIT failed so return. */
				return ffa_res;
			}
		}
	}

	return FFA_OK;
}

static ffa_result request_received_hook(struct ffa_direct_msg *req)
{
	ffa_result ffa_res = FFA_OK;

	ffa_res = deny_unexpected_rc_responses(req);
	if (ffa_res != FFA_OK)
		return ffa_res;

	state = leaf;
	own_id = req->destination_id;
	caller_id = req->source_id;
	callee_id = SP_ID_INVALID;

	if (FFA_IS_32_BIT_FUNC(req->function_id))
		req->args.args32[0] &= ~FFA_ROUTING_EXT_BITS_MASK;

	return FFA_OK;
}

ffa_result ffa_direct_msg_routing_ext_wait_post_hook(struct ffa_direct_msg *req)
{
	return request_received_hook(req);
}

ffa_result ffa_direct_msg_routing_ext_req_pre_hook(struct ffa_direct_msg *req)
{
	if (FFA_IS_32_BIT_FUNC(req->function_id)) {
		if (req->args.args32[0] & FFA_ROUTING_EXT_BITS_MASK)
			return FFA_INVALID_PARAMETERS;
	}

	state = internal;
	callee_id = req->destination_id;

	return FFA_OK;
}

ffa_result ffa_direct_msg_routing_ext_req_post_hook(struct ffa_direct_msg *resp)
{
	ffa_result ffa_res = FFA_OK;
	struct ffa_direct_msg rc_resp = { 0 };

	while (is_rc_message(resp)) {
		if (is_error_message(resp)) {
			/* The callee returned an error in an RC message. */
			ffa_res = get_error_code_from_message(resp);
			break;
		}

		/* Forwarding RC request towards the root (normal world) */
		state = forwarding;

		ffa_res = ffa_msg_send_direct_resp_32(own_id, caller_id,
						   resp->args.args32[0], resp->args.args32[1],
						   resp->args.args32[2], resp->args.args32[3],
						   resp->args.args32[4], &rc_resp);
		if (ffa_res != FFA_OK)
			goto forward_ffa_error_to_rc_root;

		/*
		 * Denying messages which are not RC responses or came from a
		 * different endpoint than the original caller.
		 */
		ffa_res = deny_unexpected_requests(&rc_resp);
		if (ffa_res != FFA_OK)
			goto forward_ffa_error_to_rc_root;

		/* Forwarding RC response towards the RC root. */
		state = internal;
		ffa_res = ffa_msg_send_direct_req_32(
			own_id, callee_id, rc_resp.args.args32[0], rc_resp.args.args32[1],
			rc_resp.args.args32[2], rc_resp.args.args32[3], rc_resp.args.args32[4],
			resp);

		goto break_on_ffa_error;

		/*
		 * At this point an FF-A error message was received while it was
		 * trying to forward the RC message. Forwarding erro to RC root.
		 */
forward_ffa_error_to_rc_root:
		ffa_res = send_rc_error_message_to_rc_root(resp, ffa_res);

break_on_ffa_error:
		if (ffa_res != FFA_OK) {
			/* Exit loop, set leaf state and return with error. */
			break;
		}
	}

	/* Non-RC message was received or a non-recoverable error happened. */
	state = leaf;
	callee_id = SP_ID_INVALID;

	return ffa_res;
}

void ffa_direct_msg_routing_ext_req_error_hook(void)
{
	state = leaf;
	callee_id = SP_ID_INVALID;
}

ffa_result ffa_direct_msg_routing_ext_resp_pre_hook(struct ffa_direct_msg *resp)
{
	if (FFA_IS_32_BIT_FUNC(resp->function_id)) {
		if (resp->args.args32[0] & FFA_ROUTING_EXT_BITS_MASK)
			return FFA_INVALID_PARAMETERS;
	}

	state = idle;
	caller_id = SP_ID_INVALID;
	callee_id = SP_ID_INVALID;

	return FFA_OK;
}

ffa_result ffa_direct_msg_routing_ext_resp_post_hook(struct ffa_direct_msg *req)
{
	return request_received_hook(req);
}

void ffa_direct_msg_routing_ext_resp_error_hook(void)
{
}

ffa_result ffa_direct_msg_routing_ext_rc_req_pre_hook(struct ffa_direct_msg *req)
{
	if (FFA_IS_32_BIT_FUNC(req->function_id)) {
		if (req->args.args32[0] & FFA_ROUTING_EXT_BITS_MASK)
			return FFA_INVALID_PARAMETERS;
	}

	req->args.args32[0] |= FFA_ROUTING_EXT_RC_BIT;
	state = rc_root;

	return FFA_OK;
}

ffa_result
ffa_direct_msg_routing_ext_rc_req_post_hook(struct ffa_direct_msg *resp)
{
	ffa_result ffa_res = FFA_OK;

	ffa_res = deny_unexpected_requests(resp);
	state = leaf;

	if (is_error_message(resp))
		ffa_res = get_error_code_from_message(resp);

	return ffa_res;
}

void ffa_direct_msg_routing_ext_rc_req_error_hook(void)
{
	state = leaf;
}
