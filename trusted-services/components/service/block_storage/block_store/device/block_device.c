/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "block_device.h"

#define BLOCK_DEVICE_PARTITION_HANDLE    (0)

psa_status_t block_device_check_access_permitted(
	const struct block_device *block_device,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	if (handle != BLOCK_DEVICE_PARTITION_HANDLE)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (!storage_partition_is_access_permitted(&block_device->storage_partition, client_id))
		return PSA_ERROR_NOT_PERMITTED;

	return PSA_SUCCESS;
}

psa_status_t block_device_get_partition_info(
	struct block_device *block_device,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info)
{
	psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;

	if (storage_partition_is_guid_matched(&block_device->storage_partition, partition_guid)) {

		info->block_size = block_device->storage_partition.block_size;
		info->num_blocks = block_device->storage_partition.num_blocks;
		info->partition_guid = block_device->storage_partition.partition_guid;

		/* A block_device has no parent so return a nil UUID */
		memset(info->parent_guid.octets, 0, sizeof(info->parent_guid.octets));

		status = PSA_SUCCESS;
	}

	return status;
}

psa_status_t block_device_open(
	struct block_device *block_device,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle)
{
	psa_status_t status = PSA_ERROR_NOT_PERMITTED;

	if (storage_partition_is_guid_matched(&block_device->storage_partition,
			partition_guid) &&
		storage_partition_is_open_permitted(&block_device->storage_partition,
			client_id, NULL)) {

		*handle = BLOCK_DEVICE_PARTITION_HANDLE;
		status = PSA_SUCCESS;
	}

	return status;
}

psa_status_t block_device_close(
	struct block_device *block_device,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	psa_status_t status = block_device_check_access_permitted(block_device, client_id, handle);

	return status;
}

struct block_store *block_device_init(
	struct block_device *block_device,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size)
{
	/* block_device exposes a single storage partition that represents the
	 * underlying storage device */
	storage_partition_init(
		&block_device->storage_partition,
		disk_guid, num_blocks, block_size);

	return &block_device->base_block_store;
}

void block_device_deinit(
	struct block_device *block_device)
{
	storage_partition_deinit(
		&block_device->storage_partition);
}

void block_device_configure(
	struct block_device *block_device,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size)
{
	storage_partition_init(
		&block_device->storage_partition,
		disk_guid, num_blocks, block_size);
}