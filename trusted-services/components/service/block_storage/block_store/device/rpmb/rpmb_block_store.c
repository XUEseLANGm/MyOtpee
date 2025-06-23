/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "rpmb_block_store.h"
#include "util.h"

static psa_status_t rpmb_block_store_get_partition_info(void *context,
							const struct uuid_octets *partition_guid,
							struct storage_partition_info *info)
{
	struct rpmb_block_store *block_store = (struct rpmb_block_store *)context;

	return block_device_get_partition_info(
		&block_store->base_block_device, partition_guid, info);
}

static psa_status_t rpmb_block_store_open(void *context, uint32_t client_id,
					  const struct uuid_octets *partition_guid,
					  storage_partition_handle_t *handle)
{
	struct rpmb_block_store *block_store = (struct rpmb_block_store *)context;

	if (!block_store)
		return PSA_ERROR_INVALID_ARGUMENT;

	return block_device_open(&block_store->base_block_device, client_id, partition_guid,
				 handle);
}

static psa_status_t rpmb_block_store_close(void *context, uint32_t client_id,
					   storage_partition_handle_t handle)
{
	struct rpmb_block_store *block_store = (struct rpmb_block_store *)context;

	if (!block_store)
		return PSA_ERROR_INVALID_ARGUMENT;

	return block_device_close(&block_store->base_block_device, client_id, handle);
}

static psa_status_t rpmb_block_store_read(void *context, uint32_t client_id,
					  storage_partition_handle_t handle, uint64_t lba,
					  size_t offset, size_t buffer_size, uint8_t *buffer,
					  size_t *data_len)
{
	struct rpmb_block_store *block_store = (struct rpmb_block_store *)context;
	const struct storage_partition *storage_partition = NULL;
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	uint8_t temp[RPMB_DATA_SIZE] = { 0 };
	size_t end_offset = 0;
	size_t copy_length = 0;

	if (!block_store)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (offset >= RPMB_DATA_SIZE)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (ADD_OVERFLOW(offset, buffer_size, &end_offset))
		return PSA_ERROR_INVALID_ARGUMENT;

	status = block_device_check_access_permitted(&block_store->base_block_device, client_id,
						     handle);
	if (status != PSA_SUCCESS)
		return status;

	storage_partition = &block_store->base_block_device.storage_partition;

	*data_len = 0;

	if (!storage_partition_is_lba_legal(storage_partition, lba))
		return PSA_ERROR_INVALID_ARGUMENT;

	status = rpmb_frontend_read(block_store->frontend, lba, temp, 1);
	if (status != PSA_SUCCESS)
		return status;

	copy_length = MIN(buffer_size, sizeof(temp) - offset);
	memcpy(buffer, temp + offset, copy_length);

	*data_len += copy_length;

	return status;
}

static psa_status_t rpmb_block_store_write(void *context, uint32_t client_id,
					   storage_partition_handle_t handle, uint64_t lba,
					   size_t offset, const uint8_t *data, size_t data_len,
					   size_t *num_written)
{
	struct rpmb_block_store *block_store = (struct rpmb_block_store *)context;
	const struct storage_partition *storage_partition = NULL;
	uint8_t temp[RPMB_DATA_SIZE] = { 0 };
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	size_t copy_length = 0;

	if (!block_store)
		return PSA_ERROR_INVALID_ARGUMENT;

	status = block_device_check_access_permitted(&block_store->base_block_device, client_id,
						     handle);
	if (status != PSA_SUCCESS)
		return status;

	storage_partition = &block_store->base_block_device.storage_partition;

	if (!storage_partition_is_lba_legal(storage_partition, lba))
		return PSA_ERROR_INVALID_ARGUMENT;

	copy_length = MIN(data_len, sizeof(temp) - offset);
	if (copy_length != sizeof(temp)) {
		status = rpmb_frontend_read(block_store->frontend, lba, temp, 1);
		if (status != PSA_SUCCESS)
			return status;
	}

	memcpy(temp + offset, data, copy_length);

	status = rpmb_frontend_write(block_store->frontend, lba, temp, 1);
	if (status != PSA_SUCCESS)
		return status;

	*num_written += copy_length;

	return status;
}

static psa_status_t rpmb_block_store_erase(void *context, uint32_t client_id,
					   storage_partition_handle_t handle, uint64_t begin_lba,
					   size_t num_blocks)
{
	(void)context;
	(void)client_id;
	(void)handle;
	(void)begin_lba;
	(void)num_blocks;

	return PSA_SUCCESS;
}

struct block_store *rpmb_block_store_init(struct rpmb_block_store *block_store,
					  const struct uuid_octets *disk_guid,
					  struct rpmb_frontend *frontend)
{
	static const struct block_store_interface interface = {
		rpmb_block_store_get_partition_info,
		rpmb_block_store_open,
		rpmb_block_store_close,
		rpmb_block_store_read,
		rpmb_block_store_write,
		rpmb_block_store_erase
	};
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	size_t num_blocks = 0;
	size_t block_size = 0;

	block_store->frontend = frontend;
	block_store->base_block_device.base_block_store.context = block_store;
	block_store->base_block_device.base_block_store.interface = &interface;

	status = rpmb_frontend_block_count(frontend, &num_blocks);
	if (status != PSA_SUCCESS)
		return NULL;

	status = rpmb_frontend_block_size(frontend, &block_size);
	if (status != PSA_SUCCESS)
		return NULL;

	return block_device_init(&block_store->base_block_device, disk_guid, num_blocks,
				 block_size);
}

void rpmb_block_store_deinit(struct rpmb_block_store *block_store)
{
	/* TODO: close session */
	block_device_deinit(&block_store->base_block_device);
}
