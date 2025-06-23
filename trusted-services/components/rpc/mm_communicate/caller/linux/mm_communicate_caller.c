/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mm_communicate_caller.h"
#include "carveout.h"
#include "util.h"
#include <arm_ffa_user.h>
#include <components/rpc/mm_communicate/common/mm_communicate_call_args.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/common/mm/mm_smc.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define KERNEL_MOD_REQ_VER_MAJOR 5
#define KERNEL_MOD_REQ_VER_MINOR 0
#define KERNEL_MOD_REQ_VER_PATCH 0

struct mm_communicate_caller_context {
	int ffa_fd;
	const char *ffa_device_path;
	uint16_t dest_partition_id;
	uint8_t *comm_buffer;
	size_t comm_buffer_size;
	size_t req_len;
	const struct mm_communicate_serializer *serializer;
};

static const char mm_uuid[] = "ed32d533-99e6-4209-9cc0-2d72cdd998a7";

static rpc_status_t release_shared_memory(void *context,
					  struct rpc_caller_shared_memory *shared_memory);

static void rpc_uuid_to_efi_guid(const struct rpc_uuid *uuid, EFI_GUID *guid)
{
	guid->Data1 = uuid->uuid[0] << 24 | uuid->uuid[1] << 16 | uuid->uuid[2] << 8 |
		      uuid->uuid[3];
	guid->Data2 = uuid->uuid[4] << 8 | uuid->uuid[5];
	guid->Data3 = uuid->uuid[6] << 8 | uuid->uuid[7];
	memcpy(guid->Data4, &uuid->uuid[8], sizeof(guid->Data4));
}

static rpc_status_t mm_return_code_to_rpc_status(int32_t return_code)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	switch (return_code) {
	case MM_RETURN_CODE_NOT_SUPPORTED:
		rpc_status = RPC_ERROR_NOT_FOUND;
		break;
	case MM_RETURN_CODE_INVALID_PARAMETER:
		rpc_status = RPC_ERROR_INVALID_VALUE;
		break;
	case MM_RETURN_CODE_DENIED:
		rpc_status = RPC_ERROR_INVALID_STATE;
		break;
	case MM_RETURN_CODE_NO_MEMORY:
		rpc_status = RPC_ERROR_INTERNAL;
		break;
	default:
		break;
	}

	return rpc_status;
}

static rpc_status_t open_session(void *context, const struct rpc_uuid *service_uuid,
				 uint16_t endpoint_id)
{
	struct mm_communicate_caller_context *mm_context =
		(struct mm_communicate_caller_context *)context;
	EFI_GUID svc_guid = { 0 };

	if (!context || !service_uuid)
		return RPC_ERROR_INVALID_VALUE;

	if (mm_context->ffa_fd >= 0)
		return RPC_ERROR_INVALID_STATE;

	rpc_uuid_to_efi_guid(service_uuid, &svc_guid);

	mm_context->serializer = mm_communicate_serializer_find(&svc_guid);
	if (!mm_context->serializer)
		return RPC_ERROR_INTERNAL;

	if (!mm_context->ffa_device_path) {
		mm_context->serializer = NULL;
		return RPC_ERROR_INTERNAL;
	}

	mm_context->ffa_fd = open(mm_context->ffa_device_path, O_RDWR);
	if (mm_context->ffa_fd < 0) {
		mm_context->serializer = NULL;
		return RPC_ERROR_INTERNAL;
	}

	mm_context->dest_partition_id = endpoint_id;

	return RPC_SUCCESS;
}

static rpc_status_t find_and_open_session(void *context, const struct rpc_uuid *service_uuid)
{
	struct mm_communicate_caller_context *mm_context =
		(struct mm_communicate_caller_context *)context;
	int fd = 0;
	int status = 0;
	struct ffa_ioctl_ep_desc discovered_partition = { 0 };

	if (!context || !service_uuid)
		return RPC_ERROR_INVALID_VALUE;

	if (mm_context->ffa_fd >= 0)
		return RPC_ERROR_INVALID_STATE;

	if (!mm_context->ffa_device_path)
		return RPC_ERROR_INTERNAL;

	fd = open(mm_context->ffa_device_path, O_RDWR);
	if (fd < 0)
		return RPC_ERROR_INTERNAL;

	discovered_partition.uuid_ptr = (uintptr_t)&mm_uuid;
	discovered_partition.id = 0;

	status = ioctl(fd, FFA_IOC_GET_PART_ID, &discovered_partition);
	if (status < 0) {
		close(fd);
		return RPC_ERROR_INTERNAL;
	}

	status = close(fd);
	if (status < 0)
		return RPC_ERROR_INTERNAL;

	return open_session(context, service_uuid, discovered_partition.id);
}

static rpc_status_t close_session(void *context)
{
	struct mm_communicate_caller_context *mm_context =
		(struct mm_communicate_caller_context *)context;
	int status = -1;

	if (!context)
		return RPC_ERROR_INVALID_VALUE;

	if (mm_context->ffa_fd < 0)
		return RPC_ERROR_INVALID_STATE;

	if (mm_context->comm_buffer) {
		struct rpc_caller_shared_memory memory = { 0 };
		rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

		memory.id = 0;
		memory.buffer = mm_context->comm_buffer;
		memory.size = mm_context->comm_buffer_size;

		rpc_status = release_shared_memory(context, &memory);
		if (rpc_status != RPC_SUCCESS)
			return rpc_status;
	}

	status = close(mm_context->ffa_fd);
	if (status < 0)
		return RPC_ERROR_INTERNAL;

	mm_context->ffa_fd = -1;
	mm_context->dest_partition_id = 0;
	mm_context->serializer = NULL;

	return RPC_SUCCESS;
}

static bool is_valid_shared_memory(const struct mm_communicate_caller_context *mm_context,
				   const struct rpc_caller_shared_memory *shared_memory)
{
	uintptr_t comm_buffer_end = 0;
	uintptr_t shared_memory_end = 0;

	if (ADD_OVERFLOW((uintptr_t)mm_context->comm_buffer,
			 (uintptr_t)mm_context->comm_buffer_size, &comm_buffer_end))
		return false;

	if (ADD_OVERFLOW((uintptr_t)shared_memory->buffer, (uintptr_t)shared_memory->size,
			 &shared_memory_end))
		return false;

	return (uintptr_t)mm_context->comm_buffer <= (uintptr_t)shared_memory->buffer &&
	       shared_memory_end <= comm_buffer_end;
}

static rpc_status_t create_shared_memory(void *context, size_t size,
					 struct rpc_caller_shared_memory *shared_memory)
{
	struct mm_communicate_caller_context *mm_context =
		(struct mm_communicate_caller_context *)context;
	size_t hdr_size = 0;
	size_t required_size = 0;
	int status = -1;

	if (!context || !shared_memory)
		return RPC_ERROR_INVALID_VALUE;

	*shared_memory = (struct rpc_caller_shared_memory){ 0 };

	if (!mm_context->serializer || mm_context->comm_buffer)
		return RPC_ERROR_INVALID_STATE;

	hdr_size = mm_communicate_serializer_header_size(mm_context->serializer);
	if (!hdr_size)
		return RPC_ERROR_INTERNAL;

	status = carveout_claim(&mm_context->comm_buffer, &mm_context->comm_buffer_size);
	if (status) {
		mm_context->comm_buffer = NULL;
		mm_context->comm_buffer_size = 0;

		return RPC_ERROR_INTERNAL;
	}

	if (ADD_OVERFLOW(hdr_size, size, &required_size) ||
	    required_size > mm_context->comm_buffer_size) {
		carveout_relinquish(mm_context->comm_buffer, mm_context->comm_buffer_size);
		mm_context->comm_buffer = NULL;
		mm_context->comm_buffer_size = 0;

		return RPC_ERROR_INVALID_VALUE;
	}

	shared_memory->id = 0;
	shared_memory->buffer = &mm_context->comm_buffer[hdr_size];
	shared_memory->size = mm_context->comm_buffer_size - hdr_size;

	return RPC_SUCCESS;
}

static rpc_status_t release_shared_memory(void *context,
					  struct rpc_caller_shared_memory *shared_memory)
{
	struct mm_communicate_caller_context *mm_context =
		(struct mm_communicate_caller_context *)context;

	if (!context || !shared_memory)
		return RPC_ERROR_INVALID_VALUE;

	if (!mm_context->comm_buffer)
		return RPC_ERROR_INVALID_STATE;

	if (!is_valid_shared_memory(mm_context, shared_memory))
		return RPC_ERROR_INVALID_VALUE;

	memset(mm_context->comm_buffer, 0x00, mm_context->comm_buffer_size);

	carveout_relinquish(mm_context->comm_buffer, mm_context->comm_buffer_size);
	mm_context->comm_buffer = NULL;
	mm_context->comm_buffer_size = 0;

	return RPC_SUCCESS;
}

static rpc_status_t call(void *context, uint16_t opcode,
			 struct rpc_caller_shared_memory *shared_memory, size_t request_length,
			 size_t *response_length, service_status_t *service_status)
{
	struct mm_communicate_caller_context *mm_context =
		(struct mm_communicate_caller_context *)context;
	struct ffa_ioctl_msg_args direct_msg = { 0 };
	int kernel_op_status = 0;
	int32_t mm_return_code = 0;
	uint8_t *resp_buf = NULL;

	if (!context || !shared_memory || !response_length || !service_status)
		return RPC_ERROR_INVALID_VALUE;

	if (!is_valid_shared_memory(mm_context, shared_memory))
		return RPC_ERROR_INVALID_VALUE;

	mm_communicate_serializer_header_encode(mm_context->serializer, mm_context->comm_buffer,
						opcode, request_length);

	/* Make direct call to send the request */
	direct_msg.dst_id = mm_context->dest_partition_id;
	direct_msg.args[MM_COMMUNICATE_CALL_ARGS_COMM_BUFFER_OFFSET] = 0;

	kernel_op_status = ioctl(mm_context->ffa_fd, FFA_IOC_MSG_SEND, &direct_msg);
	if (kernel_op_status < 0)
		return RPC_ERROR_INTERNAL;

	/* Kernel send operation completed normally */
	mm_return_code = direct_msg.args[MM_COMMUNICATE_CALL_ARGS_RETURN_CODE];
	if (mm_return_code != MM_RETURN_CODE_SUCCESS)
		return mm_return_code_to_rpc_status(mm_return_code);

	mm_communicate_serializer_header_decode(mm_context->serializer, mm_context->comm_buffer,
						(efi_status_t *)service_status, &resp_buf,
						response_length);

	if (resp_buf != shared_memory->buffer)
		return RPC_ERROR_INVALID_RESPONSE_BODY;

	return RPC_SUCCESS;
}

static bool mm_communicate_caller_check_version(void)
{
	FILE *f = NULL;
	char mod_name[64] = { 0 };
	int ver_major = 0, ver_minor = 0, ver_patch = 0;
	bool mod_loaded = false;

	f = fopen("/proc/modules", "r");
	if (!f) {
		printf("error: cannot open /proc/modules\n");
		return false;
	}

	while (fscanf(f, "%63s %*[^\n]\n", mod_name) != EOF) {
		if (!strcmp(mod_name, "arm_ffa_user")) {
			mod_loaded = true;
			break;
		}
	}

	fclose(f);

	if (!mod_loaded) {
		printf("error: kernel module not loaded\n");
		return false;
	}

	f = fopen("/sys/module/arm_ffa_user/version", "r");
	if (f) {
		fscanf(f, "%d.%d.%d", &ver_major, &ver_minor, &ver_patch);
		fclose(f);
	} else {
		/*
		 * Fallback for the initial release of the kernel module, where
		 * the version definition was missing.
		 */
		ver_major = 1;
		ver_minor = 0;
		ver_patch = 0;
	}

	if (ver_major != KERNEL_MOD_REQ_VER_MAJOR)
		goto err;

	if (ver_minor < KERNEL_MOD_REQ_VER_MINOR)
		goto err;

	if (ver_minor == KERNEL_MOD_REQ_VER_MINOR)
		if (ver_patch < KERNEL_MOD_REQ_VER_PATCH)
			goto err;

	return true;

err:
	printf("error: kernel module is v%d.%d.%d but required v%d.%d.%d\n", ver_major, ver_minor,
	       ver_patch, KERNEL_MOD_REQ_VER_MAJOR, KERNEL_MOD_REQ_VER_MINOR,
	       KERNEL_MOD_REQ_VER_PATCH);

	return false;
}

rpc_status_t mm_communicate_caller_init(struct rpc_caller_interface *rpc_caller,
					const char *ffa_device_path)
{
	struct mm_communicate_caller_context *context = NULL;

	if (!rpc_caller || !ffa_device_path)
		return RPC_ERROR_INVALID_VALUE;

	if (!mm_communicate_caller_check_version())
		return RPC_ERROR_INTERNAL;

	context = (struct mm_communicate_caller_context *)calloc(
		1, sizeof(struct mm_communicate_caller_context));
	if (!context)
		return RPC_ERROR_INTERNAL;

	context->ffa_fd = -1;
	context->ffa_device_path = ffa_device_path;
	context->dest_partition_id = 0;
	context->comm_buffer = NULL;
	context->comm_buffer_size = 0;
	context->req_len = 0;
	context->serializer = NULL;

	rpc_caller->context = context;
	rpc_caller->open_session = open_session;
	rpc_caller->find_and_open_session = find_and_open_session;
	rpc_caller->close_session = close_session;
	rpc_caller->create_shared_memory = create_shared_memory;
	rpc_caller->release_shared_memory = release_shared_memory;
	rpc_caller->call = call;

	return RPC_SUCCESS;
}

rpc_status_t mm_communicate_caller_deinit(struct rpc_caller_interface *rpc_caller)
{
	struct mm_communicate_caller_context *mm_context = NULL;
	rpc_status_t status = RPC_ERROR_INTERNAL;

	if (!rpc_caller || !rpc_caller->context)
		return RPC_ERROR_INVALID_VALUE;

	mm_context = (struct mm_communicate_caller_context *)rpc_caller->context;

	if (mm_context->comm_buffer) {
		carveout_relinquish(mm_context->comm_buffer, mm_context->comm_buffer_size);
		mm_context->comm_buffer = NULL;
		mm_context->comm_buffer_size = 0;
	}

	if (mm_context->ffa_fd >= 0) {
		status = rpc_caller_close_session(rpc_caller);
		if (status != RPC_SUCCESS)
			return status;
	}

	free(rpc_caller->context);
	rpc_caller->context = NULL;

	return RPC_SUCCESS;
}
