/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <string.h>
#include "common/tlv/tlv.h"
#include "common/endian/le.h"
#include "protocols/rpc/common/packed-c/status.h"
#include "protocols/service/block_storage/packed-c/messages.h"
#include "packedc_block_storage_serializer.h"


/* Operation: get_partition_info */
rpc_status_t deserialize_get_partition_info_req(const struct rpc_buffer *req_buf,
	struct uuid_octets *partition_guid)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_block_storage_get_partition_info_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_block_storage_get_partition_info_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		memcpy(&partition_guid->octets, recv_msg.partition_guid, sizeof(partition_guid->octets));
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

rpc_status_t serialize_get_partition_info_resp(struct rpc_buffer *resp_buf,
	struct storage_partition_info *info)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_block_storage_get_partition_info_out resp_msg;
	size_t fixed_len = sizeof(struct ts_block_storage_get_partition_info_out);

	resp_msg.num_blocks = info->num_blocks;
	resp_msg.block_size = info->block_size;

	memcpy(resp_msg.partition_guid,
		info->partition_guid.octets, TS_BLOCK_STORAGE_GUID_OCTET_LEN);

	memcpy(resp_msg.parent_guid,
		info->parent_guid.octets, TS_BLOCK_STORAGE_GUID_OCTET_LEN);

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: open */
rpc_status_t deserialize_open_req(const struct rpc_buffer *req_buf,
	struct uuid_octets *partition_guid)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_block_storage_open_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_block_storage_open_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		memcpy(&partition_guid->octets, recv_msg.partition_guid, sizeof(partition_guid->octets));
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

rpc_status_t serialize_open_resp(struct rpc_buffer *resp_buf,
	storage_partition_handle_t handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_block_storage_open_out resp_msg;
	size_t fixed_len = sizeof(struct ts_block_storage_open_out);

	resp_msg.handle = handle;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: close */
rpc_status_t deserialize_close_req(const struct rpc_buffer *req_buf,
	storage_partition_handle_t *handle)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_block_storage_close_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_block_storage_close_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*handle = recv_msg.handle;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: read */
rpc_status_t deserialize_read_req(const struct rpc_buffer *req_buf,
	storage_partition_handle_t *handle,
	uint64_t *lba,
	size_t *offset,
	size_t *len)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_block_storage_read_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_block_storage_read_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);
		*handle = recv_msg.handle;
		*lba = recv_msg.lba;
		*offset = recv_msg.offset;
		*len = recv_msg.len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: write */
rpc_status_t deserialize_write_req(const struct rpc_buffer *req_buf,
	storage_partition_handle_t *handle,
	uint64_t *lba,
	size_t *offset,
	const uint8_t **data,
	size_t *data_length)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_block_storage_write_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_block_storage_write_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*handle = recv_msg.handle;
		*lba = recv_msg.lba;
		*offset = recv_msg.offset;

		*data = (const uint8_t*)req_buf->data + expected_fixed_len;
		*data_length = req_buf->data_length - expected_fixed_len;

		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

rpc_status_t serialize_write_resp(struct rpc_buffer *resp_buf,
	size_t num_written)
{
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	struct ts_block_storage_write_out resp_msg;
	size_t fixed_len = sizeof(struct ts_block_storage_write_out);

	resp_msg.num_written = num_written;

	if (fixed_len <= resp_buf->size) {

		memcpy(resp_buf->data, &resp_msg, fixed_len);
		resp_buf->data_length = fixed_len;
		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Operation: erase */
rpc_status_t deserialize_erase_req(const struct rpc_buffer *req_buf,
	storage_partition_handle_t *handle,
	uint64_t *begin_lba,
	size_t *num_blocks)
{
	rpc_status_t rpc_status = RPC_ERROR_INVALID_REQUEST_BODY;
	struct ts_block_storage_erase_in recv_msg;
	size_t expected_fixed_len = sizeof(struct ts_block_storage_erase_in);

	if (expected_fixed_len <= req_buf->data_length) {

		memcpy(&recv_msg, req_buf->data, expected_fixed_len);

		*handle = recv_msg.handle;
		*begin_lba = recv_msg.begin_lba;
		*num_blocks = (size_t)recv_msg.num_blocks;

		rpc_status = RPC_SUCCESS;
	}

	return rpc_status;
}

/* Singleton method to provide access to the serializer instance */
const struct block_storage_serializer *packedc_block_storage_serializer_instance(void)
{
	static const struct block_storage_serializer instance =
	{
		deserialize_get_partition_info_req,
		serialize_get_partition_info_resp,
		deserialize_open_req,
		serialize_open_resp,
		deserialize_close_req,
		deserialize_read_req,
		deserialize_write_req,
		serialize_write_resp,
		deserialize_erase_req
	};

	return &instance;
}
