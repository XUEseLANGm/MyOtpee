/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "linuxffa_service_context.h"
#include "components/rpc/ts_rpc/caller/linux/ts_rpc_caller_linux.h"
#include <stdlib.h>
#include <string.h>

struct linux_ts_service_context
{
    struct service_context service_context;
    struct rpc_caller_interface caller;
    struct rpc_uuid service_uuid;
};

/* Concrete service_context methods */
static struct rpc_caller_session *linux_ts_service_context_open(void *context);
static void linux_ts_service_context_close(void *context, struct rpc_caller_session *session);
static void linux_ts_service_context_relinquish(void *context);


struct linux_ts_service_context *linux_ts_service_context_create(const struct rpc_uuid *service_uuid)

{
	struct linux_ts_service_context *new_context = NULL;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	if (!service_uuid)
		return NULL;

	new_context = (struct linux_ts_service_context *)
		calloc(1, sizeof(struct linux_ts_service_context));
	if (!new_context)
		return NULL;

	rpc_status = ts_rpc_caller_linux_init(&new_context->caller);
	if (rpc_status != RPC_SUCCESS) {
		free(new_context);
		return NULL;
	}

	memcpy(&new_context->service_uuid, service_uuid, sizeof(new_context->service_uuid));

	new_context->service_context.context = new_context;
	new_context->service_context.open = linux_ts_service_context_open;
	new_context->service_context.close = linux_ts_service_context_close;
	new_context->service_context.relinquish = linux_ts_service_context_relinquish;

	return new_context;
}

static struct rpc_caller_session *linux_ts_service_context_open(void *context)
{
	struct linux_ts_service_context *this_context = (struct linux_ts_service_context *)context;
	struct rpc_caller_session *session = NULL;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	if (!context)
		return NULL;

	session = (struct rpc_caller_session *)calloc(1, sizeof(struct rpc_caller_session));
	if (!session)
		return NULL;

	rpc_status = rpc_caller_session_find_and_open(session, &this_context->caller,
						      &this_context->service_uuid, 8192);
	if (rpc_status != RPC_SUCCESS) {
		free(session);
		return NULL;
	}

	return session;
}

static void linux_ts_service_context_close(void *context, struct rpc_caller_session *session)
{
	(void)context;

	if (!session)
		return;

	rpc_caller_session_close(session);
	free(session);
}

static void linux_ts_service_context_relinquish(void *context)
{
	struct linux_ts_service_context *this_context = (struct linux_ts_service_context *)context;

	if (!context)
		return;

	ts_rpc_caller_linux_deinit(&this_context->caller);
	free(context);
}