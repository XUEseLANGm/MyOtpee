/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "rpc_caller_session.h"
#include "block_storage_client.h"
#include "protocols/rpc/common/packed-c/status.h"
#include "protocols/service/block_storage/packed-c/messages.h"
#include "protocols/service/block_storage/packed-c/opcodes.h"

static psa_status_t block_storage_client_get_partition_info(void *context,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info)
{
	struct block_storage_client *this_context = (struct block_storage_client *)context;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_block_storage_get_partition_info_in req_msg = {0};
	size_t req_len = sizeof(req_msg);
	uint8_t *req_buf = NULL;

	memcpy(req_msg.partition_guid, partition_guid->octets, sizeof(req_msg.partition_guid));

	rpc_call_handle call_handle =
		rpc_caller_session_begin(this_context->client.session, &req_buf, req_len,
					 sizeof(struct ts_block_storage_get_partition_info_out));

	if (call_handle) {
		uint8_t *resp_buf = NULL;
		size_t resp_len = 0;
		service_status_t service_status = 0;

		memcpy(req_buf, &req_msg, req_len);

		this_context->client.rpc_status = rpc_caller_session_invoke(
			call_handle, TS_BLOCK_STORAGE_OPCODE_GET_PARTITION_INFO, &resp_buf,
			&resp_len, &service_status);

		if (this_context->client.rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >=
				    sizeof(struct ts_block_storage_get_partition_info_out)) {

					struct ts_block_storage_get_partition_info_out resp_msg;

					memcpy(&resp_msg, resp_buf, sizeof(resp_msg));

					info->block_size = resp_msg.block_size;
					info->num_blocks = resp_msg.num_blocks;

					memcpy(info->partition_guid.octets,
						resp_msg.partition_guid,
						TS_BLOCK_STORAGE_GUID_OCTET_LEN);

					memcpy(info->parent_guid.octets,
						resp_msg.parent_guid,
						TS_BLOCK_STORAGE_GUID_OCTET_LEN);
				}
				else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_session_end(call_handle);
	} else {

		this_context->client.rpc_status = RPC_ERROR_INTERNAL;
	}

	return psa_status;
}

static psa_status_t block_storage_client_open(void *context,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle)
{
	struct block_storage_client *this_context = (struct block_storage_client *)context;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_block_storage_open_in req_msg = {0};
	size_t req_len = sizeof(req_msg);
	uint8_t *req_buf = NULL;

	(void)client_id;

	memcpy(req_msg.partition_guid, partition_guid->octets, sizeof(req_msg.partition_guid));

	rpc_call_handle call_handle =
		rpc_caller_session_begin(this_context->client.session, &req_buf, req_len,
					 sizeof(struct ts_block_storage_open_out));

	if (call_handle) {

		uint8_t *resp_buf = NULL;
		size_t resp_len = 0;
		service_status_t service_status = 0;

		memcpy(req_buf, &req_msg, req_len);

		this_context->client.rpc_status = rpc_caller_session_invoke(
			call_handle, TS_BLOCK_STORAGE_OPCODE_OPEN, &resp_buf, &resp_len,
			&service_status);

		if (this_context->client.rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_block_storage_open_out)) {

					struct ts_block_storage_open_out resp_msg;

					memcpy(&resp_msg, resp_buf, sizeof(resp_msg));
					*handle = resp_msg.handle;
				} else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_session_end(call_handle);
	} else {

		this_context->client.rpc_status = RPC_ERROR_INTERNAL;
	}

	return psa_status;
}

static psa_status_t block_storage_client_close(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	struct block_storage_client *this_context = (struct block_storage_client *)context;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_block_storage_close_in req_msg = {0};
	size_t req_len = sizeof(req_msg);
	uint8_t *req_buf = NULL;

	(void)client_id;

	req_msg.handle = handle;

	rpc_call_handle call_handle =
		rpc_caller_session_begin(this_context->client.session, &req_buf, req_len, 0);

	if (call_handle) {

		uint8_t *resp_buf = NULL;
		size_t resp_len = 0;
		service_status_t service_status = 0;

		memcpy(req_buf, &req_msg, req_len);

		this_context->client.rpc_status = rpc_caller_session_invoke(
			call_handle, TS_BLOCK_STORAGE_OPCODE_CLOSE,
			&resp_buf, &resp_len, &service_status);

		if (this_context->client.rpc_status == RPC_SUCCESS)
			psa_status = service_status;

		rpc_caller_session_end(call_handle);
	} else {

		this_context->client.rpc_status = RPC_ERROR_INTERNAL;
	}

	return psa_status;
}

static psa_status_t block_storage_client_read(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	size_t buffer_size,
	uint8_t *buffer,
	size_t *data_len)
{
	struct block_storage_client *this_context = (struct block_storage_client *)context;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_block_storage_read_in req_msg = {0};
	size_t req_len = sizeof(req_msg);
	uint8_t *req_buf = NULL;

	(void)client_id;

	*data_len = 0;

	req_msg.handle = handle;
	req_msg.lba = lba;
	req_msg.offset = offset;
	req_msg.len = buffer_size;

	rpc_call_handle call_handle =
		rpc_caller_session_begin(this_context->client.session, &req_buf, req_len,
					 buffer_size);

	if (call_handle) {

		uint8_t *resp_buf = NULL;
		size_t resp_len = 0;
		service_status_t service_status = 0;

		memcpy(req_buf, &req_msg, req_len);

		this_context->client.rpc_status = rpc_caller_session_invoke(
			call_handle, TS_BLOCK_STORAGE_OPCODE_READ, &resp_buf, &resp_len,
			&service_status);

		if (this_context->client.rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len <= buffer_size) {

					memcpy(buffer, resp_buf, resp_len);
					*data_len = resp_len;
				} else {

					psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
				}
			}
		}

		rpc_caller_session_end(call_handle);
	} else {

		this_context->client.rpc_status = RPC_ERROR_INTERNAL;
	}

	return psa_status;
}

static psa_status_t block_storage_client_write(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	const uint8_t *data,
	size_t data_len,
	size_t *num_written)
{
	struct block_storage_client *this_context = (struct block_storage_client *)context;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_block_storage_write_in req_msg = {0};
	size_t req_len = sizeof(req_msg) + data_len;
	uint8_t *req_buf = NULL;

	(void)client_id;

	req_msg.handle = handle;
	req_msg.lba = lba;
	req_msg.offset = offset;

	rpc_call_handle call_handle =
		rpc_caller_session_begin(this_context->client.session, &req_buf, req_len,
					 sizeof(struct ts_block_storage_write_out));

	if (call_handle) {
		uint8_t *resp_buf = NULL;
		size_t resp_len = 0;
		service_status_t service_status = 0;

		/* Copy fixed size message */
		memcpy(req_buf, &req_msg, sizeof(req_msg));

		/* Copy variable length data */
		memcpy(&req_buf[sizeof(req_msg)], data, data_len);

		this_context->client.rpc_status = rpc_caller_session_invoke(
			call_handle, TS_BLOCK_STORAGE_OPCODE_WRITE,
			&resp_buf, &resp_len, &service_status);

		if (this_context->client.rpc_status == RPC_SUCCESS) {

			psa_status = service_status;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_block_storage_write_out)) {

					struct ts_block_storage_write_out resp_msg;

					memcpy(&resp_msg, resp_buf, sizeof(resp_msg));
					*num_written = resp_msg.num_written;
				} else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_session_end(call_handle);
	} else {

		this_context->client.rpc_status = RPC_ERROR_INTERNAL;
	}

	return psa_status;
}

static psa_status_t block_storage_client_erase(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t begin_lba,
	size_t num_blocks)
{
	struct block_storage_client *this_context = (struct block_storage_client *)context;
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_block_storage_erase_in req_msg = {0};
	size_t req_len = sizeof(req_msg);
	uint8_t *req_buf = NULL;

	(void)client_id;

	req_msg.handle = handle;
	req_msg.begin_lba = begin_lba;
	req_msg.num_blocks = num_blocks;

	rpc_call_handle call_handle =
		rpc_caller_session_begin(this_context->client.session, &req_buf, req_len, 0);

	if (call_handle) {

		uint8_t *resp_buf = NULL;
		size_t resp_len = 0;
		service_status_t service_status = 0;

		/* Copy fixed size message */
		memcpy(req_buf, &req_msg, sizeof(req_msg));

		this_context->client.rpc_status = rpc_caller_session_invoke(
			call_handle, TS_BLOCK_STORAGE_OPCODE_ERASE,
			&resp_buf, &resp_len, &service_status);

		if (this_context->client.rpc_status == RPC_SUCCESS)
			psa_status = service_status;

		rpc_caller_session_end(call_handle);
	} else {

		this_context->client.rpc_status = RPC_ERROR_INTERNAL;
	}

	return psa_status;
}

struct block_store *block_storage_client_init(
	struct block_storage_client *block_storage_client,
	struct rpc_caller_session *session)
{
	service_client_init(&block_storage_client->client, session);

	/* Define concrete block store interface */
	static const struct block_store_interface interface = {
		block_storage_client_get_partition_info,
		block_storage_client_open,
		block_storage_client_close,
		block_storage_client_read,
		block_storage_client_write,
		block_storage_client_erase
	};

	/* Initialize base block_store */
	block_storage_client->base_block_store.context = block_storage_client;
	block_storage_client->base_block_store.interface = &interface;

	return &block_storage_client->base_block_store;
}

void block_storage_client_deinit(
	struct block_storage_client *block_storage_client)
{
	service_client_deinit(&block_storage_client->client);
}
