/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 */

#include "log_provider.h"

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include "components/service/log/common/log_status.h"
#include "log_uuid.h"
#include "protocols/rpc/common/packed-c/status.h"
#include "protocols/service/log/packed-c/log_proto.h"
#include "util.h"

static rpc_status_t log_puts_handler(void *context, struct rpc_request *req);

static const struct service_handler handler_table[] = { { TS_LOG_OPCODE_PUTS, log_puts_handler } };

struct rpc_service_interface *log_provider_init(struct log_provider *context,
						struct log_backend *backend)
{
	const struct rpc_uuid service_uuid = { .uuid = TS_LOG_SERVICE_UUID };

	if (context == NULL || backend == NULL)
		return NULL;

	service_provider_init(&context->base_provider, context, &service_uuid, handler_table,
			      ARRAY_SIZE(handler_table));

	context->backend = backend;

	return service_provider_get_rpc_interface(&context->base_provider);
}

/*
 * Handler function for provider to call puts operation of the attached backend.
 */
static rpc_status_t log_puts_handler(void *context, struct rpc_request *req)
{
	struct log_provider *this_context = (struct log_provider *)context;
	struct log_request *request_desc = NULL;
	size_t request_data_length = 0;

	/* Checking if the descriptor fits into the request buffer */
	if (req->request.data_length < sizeof(struct log_request))
		return TS_RPC_ERROR_INVALID_REQ_BODY;

	request_desc = (struct log_request *)(req->request.data);

	/* Checking for overflow */
	if (ADD_OVERFLOW(sizeof(*request_desc), request_desc->msg_length, &request_data_length))
		return TS_RPC_ERROR_INVALID_REQ_BODY;

	/* Checking if descriptor and data fits into the request buffer */
	if (req->request.data_length < request_data_length)
		return TS_RPC_ERROR_INVALID_REQ_BODY;

	/* Make sure it is null terminated */
	if (request_desc->msg_length != 0)
		request_desc->msg[request_desc->msg_length - 1] = '\0';

	this_context->backend->interface->puts(this_context->backend->context, request_desc->msg);
	req->service_status = LOG_STATUS_SUCCESS;

	return RPC_SUCCESS;
}
