/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <rpc/mm_communicate/caller/linux/mm_communicate_caller.h>
#include "mm_communicate_service_context.h"
#include <stdlib.h>
#include <string.h>

/* Concrete service_context methods */
static struct rpc_caller_session *mm_communicate_service_context_open(void *context);
static void mm_communicate_service_context_close(void *context,
	struct rpc_caller_session *session_handle);
static void mm_communicate_service_context_relinquish(void *context);

static void efi_guid_to_rpc_uuid(const EFI_GUID *guid, struct rpc_uuid *uuid)
{
	uuid->uuid[0] = (guid->Data1 >> 24) & 0xff;
	uuid->uuid[1] = (guid->Data1 >> 16) & 0xff;
	uuid->uuid[2] = (guid->Data1 >> 8) & 0xff;
	uuid->uuid[3] = guid->Data1 & 0xff;
	uuid->uuid[4] = (guid->Data2 >> 8) & 0xff;
	uuid->uuid[5] = guid->Data2 & 0xff;
	uuid->uuid[6] = (guid->Data3 >> 8) & 0xff;
	uuid->uuid[7] = guid->Data3 & 0xff;
	memcpy(&uuid->uuid[8], guid->Data4, sizeof(guid->Data4));
}

struct mm_communicate_service_context *mm_communicate_service_context_create(
	const char *dev_path,
	uint16_t partition_id,
	const EFI_GUID *svc_guid)
{
	struct mm_communicate_service_context *new_context =
		(struct mm_communicate_service_context*)calloc(1, sizeof(struct mm_communicate_service_context));
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	if (!new_context)
		return NULL;

	rpc_status = mm_communicate_caller_init(&new_context->caller, dev_path);
	if (rpc_status != RPC_SUCCESS) {
		free(new_context);
		return NULL;
	}

	new_context->partition_id = partition_id;
	new_context->svc_guid = *svc_guid;

	new_context->service_context.context = new_context;
	new_context->service_context.open = mm_communicate_service_context_open;
	new_context->service_context.close = mm_communicate_service_context_close;
	new_context->service_context.relinquish = mm_communicate_service_context_relinquish;

	return new_context;
}

static struct rpc_caller_session *mm_communicate_service_context_open(void *context)
{
	struct mm_communicate_service_context *this_context =
		(struct mm_communicate_service_context*)context;
	struct rpc_caller_session *session = (struct rpc_caller_session *)calloc(1, sizeof(struct rpc_caller_session));
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct rpc_uuid service_uuid = { 0 };

	if (!session)
		return NULL;

	efi_guid_to_rpc_uuid(&this_context->svc_guid, &service_uuid);

	/* The memory size is set to 0 because carveout configuration controls this. */
	rpc_status = rpc_caller_session_find_and_open(session, &this_context->caller,
						      &service_uuid, 0);
	if (rpc_status != RPC_SUCCESS) {
		free(session);
		return NULL;
	}

	return session;
}

static void mm_communicate_service_context_close(void *context, struct rpc_caller_session *session)
{
	(void)context;

	rpc_caller_session_close(session);
	free(session);
}

static void mm_communicate_service_context_relinquish(
	void *context)
{
	free(context);
}
