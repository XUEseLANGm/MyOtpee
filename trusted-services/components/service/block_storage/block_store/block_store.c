/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include "block_store.h"

psa_status_t block_store_get_partition_info(struct block_store *block_store,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info)
{
	assert(block_store);
	assert(block_store->interface);

	return block_store->interface->get_partition_info(block_store->context,
		partition_guid,
		info);
}

psa_status_t block_store_open(struct block_store *block_store,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle)
{
	assert(block_store);
	assert(block_store->interface);

	return block_store->interface->open(block_store->context,
		client_id,
		partition_guid,
		handle);
}

psa_status_t block_store_close(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	assert(block_store);
	assert(block_store->interface);

	return block_store->interface->close(block_store->context,
		client_id,
		handle);
}

psa_status_t block_store_read(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	size_t buffer_size,
	uint8_t *buffer,
	size_t *data_len)
{
	assert(block_store);
	assert(block_store->interface);

	return block_store->interface->read(block_store->context,
		client_id,
		handle,
		lba,
		offset,
		buffer_size,
		buffer,
		data_len);
}

psa_status_t block_store_write(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	const uint8_t *data,
	size_t data_len,
	size_t *num_written)
{
	assert(block_store);
	assert(block_store->interface);

	return block_store->interface->write(block_store->context,
		client_id,
		handle,
		lba,
		offset,
		data,
		data_len,
		num_written);
}

psa_status_t block_store_erase(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t begin_lba,
	size_t num_blocks)
{
	assert(block_store);
	assert(block_store->interface);

	return block_store->interface->erase(block_store->context,
		client_id,
		handle,
		begin_lba,
		num_blocks);
}
