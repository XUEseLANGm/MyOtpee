/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "service_client.h"
#include <stddef.h>

psa_status_t service_client_init(struct service_client *context,
				 struct rpc_caller_session *session)
{
	if (!context || !session)
		return PSA_ERROR_INVALID_ARGUMENT;

	context->session = session;
	context->rpc_status = RPC_SUCCESS;

	context->service_info.supported_encodings = 0;
	context->service_info.max_payload = 4096;

	return PSA_SUCCESS;
}

void service_client_deinit(struct service_client *context)
{
	context->session = NULL;
}

void service_client_set_service_info(struct service_client *context,
				     const struct service_info *service_info)
{
	context->service_info = *service_info;
}
