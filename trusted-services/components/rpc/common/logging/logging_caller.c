/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <protocols/rpc/common/packed-c/status.h>
#include "logging_caller.h"

static rpc_call_handle call_begin(void *context, uint8_t **req_buf, size_t req_len);
static rpc_status_t call_invoke(void *context, rpc_call_handle handle, uint32_t opcode,
			 	rpc_opstatus_t *opstatus, uint8_t **resp_buf, size_t *resp_len);
static void call_end(void *context, rpc_call_handle handle);


void logging_caller_init(
	struct logging_caller *this_instance,
	FILE *log_file)
{
	struct rpc_caller *base = &this_instance->rpc_caller;

	rpc_caller_init(base, this_instance);
	base->call_begin = call_begin;
	base->call_invoke = call_invoke;
	base->call_end = call_end;

	this_instance->attached_caller = NULL;
	this_instance->log_file = log_file;
	this_instance->call_index = 0;
}

void logging_caller_deinit(
	struct logging_caller *this_instance)
{
	this_instance->attached_caller = NULL;
}

struct rpc_caller *logging_caller_attach(
	struct logging_caller *this_instance,
	struct rpc_caller *attached_caller)
{
	this_instance->attached_caller = attached_caller;
	return &this_instance->rpc_caller;
}

static rpc_call_handle call_begin(void *context, uint8_t **req_buf, size_t req_len)
{
	struct logging_caller *this_instance = (struct logging_caller*)context;
	rpc_call_handle handle = NULL;

	if (this_instance->attached_caller) {

		handle = rpc_caller_begin(this_instance->attached_caller, req_buf, req_len);
	}

	fprintf(this_instance->log_file, "========================\n");
	fprintf(this_instance->log_file, "index: %d\n", this_instance->call_index);
	fprintf(this_instance->log_file, "req_len: %ld\n", req_len);

	if (!handle) {

		fprintf(this_instance->log_file, "ERROR: call_begin failed\n");
	}

	++this_instance->call_index;

	return handle;
}

static rpc_status_t call_invoke(void *context, rpc_call_handle handle, uint32_t opcode,
			 	rpc_opstatus_t *opstatus, uint8_t **resp_buf, size_t *resp_len)
{
	struct logging_caller *this_instance = (struct logging_caller*)context;
	rpc_status_t status = TS_RPC_ERROR_INVALID_TRANSACTION;

	if (this_instance->attached_caller) {


		status = rpc_caller_invoke(this_instance->attached_caller,
			handle, opcode, opstatus,
			resp_buf, resp_len);
	}

	fprintf(this_instance->log_file, "opcode: %d\n", opcode);
	fprintf(this_instance->log_file, "rpc_status: %d\n", status);

	if (status == TS_RPC_CALL_ACCEPTED) {

		fprintf(this_instance->log_file, "op_status: %ld\n", *opstatus);
		fprintf(this_instance->log_file, "resp_len: %ld\n", *resp_len);
	}

	fprintf(this_instance->log_file, "------------------------\n");

	return status;
}

static void call_end(void *context, rpc_call_handle handle)
{
	struct logging_caller *this_instance = (struct logging_caller*)context;

	if (this_instance->attached_caller) {

		rpc_caller_end(this_instance->attached_caller, handle);
	}
}
