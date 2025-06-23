/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "protocols/service/block_storage/packed-c/opcodes.h"
#include "protocols/rpc/common/packed-c/status.h"
#include "block_storage_provider.h"
#include "block_storage_uuid.h"

/* Service request handlers */
static rpc_status_t get_partition_info_handler(void *context, struct rpc_request *req);
static rpc_status_t open_handler(void *context, struct rpc_request *req);
static rpc_status_t close_handler(void *context, struct rpc_request *req);
static rpc_status_t read_handler(void *context, struct rpc_request *req);
static rpc_status_t write_handler(void *context, struct rpc_request *req);
static rpc_status_t erase_handler(void *context, struct rpc_request *req);

/* Handler mapping table for service */
static const struct service_handler handler_table[] = {
	{TS_BLOCK_STORAGE_OPCODE_GET_PARTITION_INFO, get_partition_info_handler},
	{TS_BLOCK_STORAGE_OPCODE_OPEN,               open_handler},
	{TS_BLOCK_STORAGE_OPCODE_CLOSE,              close_handler},
	{TS_BLOCK_STORAGE_OPCODE_READ,               read_handler},
	{TS_BLOCK_STORAGE_OPCODE_WRITE,              write_handler},
	{TS_BLOCK_STORAGE_OPCODE_ERASE,              erase_handler}
};

struct rpc_service_interface *block_storage_provider_init(
	struct block_storage_provider *context,
	struct block_store *block_store)
{
	struct rpc_service_interface *rpc_interface = NULL;
	const struct rpc_uuid block_storage_service_uuid = {
		.uuid = TS_BLOCK_STORAGE_SERVICE_UUID
	};

	if (context) {
		context->serializer = NULL;

		context->block_store = block_store;

		service_provider_init(&context->base_provider, context, &block_storage_service_uuid,
			handler_table, sizeof(handler_table)/sizeof(struct service_handler));

		rpc_interface = service_provider_get_rpc_interface(&context->base_provider);
	}

	return rpc_interface;
}

void block_storage_provider_deinit(
	struct block_storage_provider *context)
{
	(void)context;
}

void block_storage_provider_register_serializer(
	struct block_storage_provider *context,
	const struct block_storage_serializer *serializer)
{
	context->serializer = serializer;
}

static const struct block_storage_serializer* get_block_storage_serializer(
	struct block_storage_provider *context,
	const struct rpc_request *req)
{

	return context->serializer;
}

static rpc_status_t get_partition_info_handler(void *context, struct rpc_request *req)
{
	struct block_storage_provider *this_instance = (struct block_storage_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	const struct block_storage_serializer *serializer =
		get_block_storage_serializer(this_instance, req);

	struct uuid_octets partition_guid = {0};

	if (serializer)
		rpc_status = serializer->deserialize_get_partition_info_req(&req->request,
									    &partition_guid);

	if (rpc_status == RPC_SUCCESS) {

		struct storage_partition_info partition_info;

		psa_status_t op_status = block_store_get_partition_info(
			this_instance->block_store,
			&partition_guid,
			&partition_info);

		req->service_status = op_status;

		if (op_status == PSA_SUCCESS)
			rpc_status = serializer->serialize_get_partition_info_resp(
				&req->response, &partition_info);
	}

	return rpc_status;
}

static rpc_status_t open_handler(void *context, struct rpc_request *req)
{
	struct block_storage_provider *this_instance = (struct block_storage_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	const struct block_storage_serializer *serializer =
		get_block_storage_serializer(this_instance, req);

	struct uuid_octets partition_guid = {0};

	if (serializer)
		rpc_status = serializer->deserialize_open_req(&req->request, &partition_guid);

	if (rpc_status == RPC_SUCCESS) {

		storage_partition_handle_t handle = 0;

		psa_status_t op_status = block_store_open(
			this_instance->block_store,
			req->source_id,
			&partition_guid,
			&handle);

		req->service_status = op_status;

		if (op_status == PSA_SUCCESS) {
			rpc_status = serializer->serialize_open_resp(&req->response, handle);
		}
	}

	return rpc_status;
}

static rpc_status_t close_handler(void *context, struct rpc_request *req)
{
	struct block_storage_provider *this_instance = (struct block_storage_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	struct rpc_buffer *req_buf = &req->request;
	const struct block_storage_serializer *serializer =
		get_block_storage_serializer(this_instance, req);

	storage_partition_handle_t handle = 0;

	if (serializer)
		rpc_status = serializer->deserialize_close_req(req_buf, &handle);

	if (rpc_status == RPC_SUCCESS) {

		psa_status_t op_status = block_store_close(
			this_instance->block_store,
			req->source_id,
			handle);

		req->service_status = op_status;
	}

	return rpc_status;
}

static rpc_status_t read_handler(void *context, struct rpc_request *req)
{
	struct block_storage_provider *this_instance = (struct block_storage_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	struct rpc_buffer *req_buf = &req->request;
	const struct block_storage_serializer *serializer =
		get_block_storage_serializer(this_instance, req);

	storage_partition_handle_t handle = 0;
	uint64_t lba = 0;
	size_t offset = 0;
	size_t len = 0;

	if (serializer)
		rpc_status = serializer->deserialize_read_req(req_buf, &handle, &lba, &offset, &len);

	if (rpc_status == RPC_SUCCESS) {
		/* Defend against oversize read length */
		if (len > req->response.size)
			len = req->response.size;

		psa_status_t op_status = block_store_read(
			this_instance->block_store,
			req->source_id,
			handle,
			lba,
			offset,
			len,
			(uint8_t *)req->response.data,
			&req->response.data_length);

		req->service_status = op_status;
	}

	return rpc_status;
}

static rpc_status_t write_handler(void *context, struct rpc_request *req)
{
	struct block_storage_provider *this_instance = (struct block_storage_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	struct rpc_buffer *req_buf = &req->request;
	const struct block_storage_serializer *serializer =
		get_block_storage_serializer(this_instance, req);

	storage_partition_handle_t handle = 0;
	uint64_t lba = 0;
	size_t offset = 0;
	const uint8_t *data = NULL;
	size_t data_len = 0;

	if (serializer)
		rpc_status = serializer->deserialize_write_req(req_buf, &handle, &lba,
			&offset, &data, &data_len);

	if (rpc_status == RPC_SUCCESS) {

		size_t num_written = 0;

		psa_status_t op_status = block_store_write(
			this_instance->block_store,
			req->source_id,
			handle,
			lba,
			offset,
			data,
			data_len,
			&num_written);

		req->service_status = op_status;

		if (op_status == PSA_SUCCESS) {

			struct rpc_buffer *resp_buf = &req->response;
			rpc_status = serializer->serialize_write_resp(resp_buf, num_written);
		}
	}

	return rpc_status;
}

static rpc_status_t erase_handler(void *context, struct rpc_request *req)
{
	struct block_storage_provider *this_instance = (struct block_storage_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;

	struct rpc_buffer *req_buf = &req->request;
	const struct block_storage_serializer *serializer =
		get_block_storage_serializer(this_instance, req);

	storage_partition_handle_t handle = 0;
	uint64_t begin_lba = 0;
	size_t num_blocks = 0;

	if (serializer)
		rpc_status = serializer->deserialize_erase_req(req_buf, &handle,
			&begin_lba, &num_blocks);

	if (rpc_status == RPC_SUCCESS) {

		psa_status_t op_status = block_store_erase(
			this_instance->block_store,
			req->source_id,
			handle,
			begin_lba,
			num_blocks);

		req->service_status = op_status;
	}

	return rpc_status;
}
