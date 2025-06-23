/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "null_block_store.h"

static psa_status_t null_block_store_get_partition_info(void *context,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info)
{
	struct null_block_store *null_block_store = (struct null_block_store*)context;
	return block_device_get_partition_info(
		&null_block_store->base_block_device, partition_guid, info);
}

static psa_status_t null_block_store_open(void *context,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle)
{
	struct null_block_store *null_block_store = (struct null_block_store*)context;
	return block_device_open(
		&null_block_store->base_block_device, client_id, partition_guid, handle);
}

static psa_status_t null_block_store_close(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	struct null_block_store *null_block_store = (struct null_block_store*)context;
	return block_device_close(
		&null_block_store->base_block_device, client_id, handle);
}

static psa_status_t null_block_store_read(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	size_t buffer_size,
	uint8_t *buffer,
	size_t *data_len)
{
	const struct null_block_store *null_block_store = (struct null_block_store*)context;
	psa_status_t status = block_device_check_access_permitted(
		&null_block_store->base_block_device, client_id, handle);

	if (status == PSA_SUCCESS) {

		const struct storage_partition *storage_partition =
			&null_block_store->base_block_device.storage_partition;

		if (storage_partition_is_lba_legal(storage_partition, lba) &&
			(offset < storage_partition->block_size)) {

			/* Just real zeros */
			size_t bytes_remaining = storage_partition->block_size - offset;
			size_t bytes_to_read = (buffer_size < bytes_remaining) ?
				buffer_size :
				bytes_remaining;

			memset(buffer, 0, bytes_to_read);
			*data_len = bytes_to_read;
		}
		else {

			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

static psa_status_t null_block_store_write(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	const uint8_t *data,
	size_t data_len,
	size_t *num_written)
{
	struct null_block_store *null_block_store = (struct null_block_store*)context;
	psa_status_t status = block_device_check_access_permitted(
		&null_block_store->base_block_device, client_id, handle);

	if (status == PSA_SUCCESS) {

		const struct storage_partition *storage_partition =
			&null_block_store->base_block_device.storage_partition;

		if (storage_partition_is_lba_legal(storage_partition, lba) &&
			(offset < storage_partition->block_size)) {

			/* Don't actually write anything */
			size_t bytes_remaining = storage_partition->block_size - offset;
			size_t bytes_to_write = (data_len < bytes_remaining) ?
				data_len :
				bytes_remaining;

			*num_written = bytes_to_write;
		}
		else {

			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

static psa_status_t null_block_store_erase(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t begin_lba,
	size_t num_blocks)
{
	struct null_block_store *null_block_store = (struct null_block_store*)context;
	const struct storage_partition *storage_partition =
		&null_block_store->base_block_device.storage_partition;
	psa_status_t status = block_device_check_access_permitted(
		&null_block_store->base_block_device, client_id, handle);

	/* Sanitize the erase starting point */
	if ((status == PSA_SUCCESS) &&
		!storage_partition_is_lba_legal(storage_partition, begin_lba))
			status = PSA_ERROR_INVALID_ARGUMENT;

	/* Do nothing */

	return status;
}

struct block_store *null_block_store_init(
	struct null_block_store *null_block_store,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size)
{
	/* Define concrete block store interface */
	static const struct block_store_interface interface =
	{
		null_block_store_get_partition_info,
		null_block_store_open,
		null_block_store_close,
		null_block_store_read,
		null_block_store_write,
		null_block_store_erase
	};

	/* Initialize base block_store */
	null_block_store->base_block_device.base_block_store.context = null_block_store;
	null_block_store->base_block_device.base_block_store.interface = &interface;

	return block_device_init(
			&null_block_store->base_block_device, disk_guid, num_blocks, block_size);
}

void null_block_store_deinit(
	struct null_block_store *null_block_store)
{
	block_device_deinit(&null_block_store->base_block_device);
}
