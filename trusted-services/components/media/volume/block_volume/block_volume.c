/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdint.h>
#include <drivers/io/io_storage.h>
#include "block_volume.h"

/* Concrete io_dev interface functions */
static io_type_t block_volume_type(
	void);
static int block_volume_open(
	io_dev_info_t *dev_info, const uintptr_t spec, io_entity_t *entity);
static int block_volume_close(
	io_entity_t *entity);
static int block_volume_seek(
	io_entity_t *entity, int mode, signed long long offset);
static int block_volume_size(
	io_entity_t *entity, size_t *length);
static int block_volume_read(
	io_entity_t *entity, uintptr_t buffer, size_t length, size_t *length_read);
static int block_volume_write(
	io_entity_t *entity, const uintptr_t buffer, size_t length, size_t *length_written);

static const io_dev_funcs_t block_volume_dev_funcs = {
	.type		= block_volume_type,
	.open		= block_volume_open,
	.seek		= block_volume_seek,
	.size		= block_volume_size,
	.read		= block_volume_read,
	.write		= block_volume_write,
	.close		= block_volume_close,
	.dev_init	= NULL,
	.dev_close	= NULL
};

/* Concrete volume functions that extend the io_dev interface */
static int block_volume_erase(
	uintptr_t context);
static int block_volume_get_storage_ids(
	uintptr_t context,
	struct uuid_octets *partition_guid,
	struct uuid_octets *parent_guid);

int block_volume_init(
	struct block_volume *this_instance,
	struct block_store *block_store,
	const struct uuid_octets *partition_guid,
	struct volume **volume)
{
	/* Initialize base volume structure */
	volume_init(
		&this_instance->base_volume,
		&block_volume_dev_funcs,
		(uintptr_t)this_instance);

	/* Initialize block_volume specific attributes */
	this_instance->base_volume.erase = block_volume_erase;
	this_instance->base_volume.get_storage_ids = block_volume_get_storage_ids;

	this_instance->block_store = block_store;
	this_instance->partition_guid = *partition_guid;

	this_instance->file_pos = 0;
	this_instance->size = 0;
	this_instance->partition_handle = 0;

	this_instance->partition_info.block_size = 0;
	this_instance->partition_info.num_blocks = 0;

	*volume = &this_instance->base_volume;

	return 0;
}

void block_volume_deinit(
	struct block_volume *this_instance)
{
	(void)this_instance;
}

void block_volume_set_partition_guid(
	struct block_volume *this_instance,
	const struct uuid_octets *partition_guid)
{
	this_instance->partition_guid = *partition_guid;
}

static io_type_t block_volume_type(void)
{
	return IO_TYPE_BLOCK;
}

static int block_volume_open(
	io_dev_info_t *dev_info,
	const uintptr_t spec,
	io_entity_t *entity)
{
	struct block_volume *this_instance = (struct block_volume *)dev_info->info;
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;

	psa_status = block_store_get_partition_info(this_instance->block_store,
		&this_instance->partition_guid,
		&this_instance->partition_info);

	if (psa_status == PSA_SUCCESS) {

		this_instance->file_pos = 0;
		this_instance->size =
			this_instance->partition_info.block_size * this_instance->partition_info.num_blocks;

		psa_status = block_store_open(this_instance->block_store, 0,
			&this_instance->partition_guid,
			&this_instance->partition_handle);

		entity->info = (uintptr_t)this_instance;
	}

	return (psa_status == PSA_SUCCESS) ? 0 : -EPERM;
}

static int block_volume_close(
	io_entity_t *entity)
{
	struct block_volume *this_instance = (struct block_volume *)entity->info;

	psa_status_t psa_status = block_store_close(this_instance->block_store, 0,
		this_instance->partition_handle);

	if (psa_status == PSA_SUCCESS) {

		this_instance->file_pos = 0;
		this_instance->size = 0;
	}

	return (psa_status == PSA_SUCCESS) ? 0 : -ENXIO;
}

static int block_volume_seek(
	io_entity_t *entity,
	int mode,
	signed long long offset)
{
	struct block_volume *this_instance = (struct block_volume *)entity->info;

	switch (mode)
	{
		case IO_SEEK_SET:
		{
			if (offset <= this_instance->size)
				this_instance->file_pos = (size_t)offset;
			else
				return -EINVAL;
			break;
		}
		case IO_SEEK_CUR:
		{
			ssize_t target_pos = this_instance->file_pos + offset;
			if ((target_pos >= 0) && (target_pos <= this_instance->size))
				this_instance->file_pos = (size_t)target_pos;
			else
				return -EINVAL;
			break;
		}
		default:
			return -EINVAL;
	}

	return 0;
}

static int block_volume_size(
	io_entity_t *entity,
	size_t *length)
{
	struct block_volume *this_instance = (struct block_volume *)entity->info;
	*length = this_instance->size;
	return 0;
}

static int block_volume_read(
	io_entity_t *entity,
	uintptr_t buffer,
	size_t length,
	size_t *length_read)
{
	struct block_volume *this_instance = (struct block_volume *)entity->info;
	size_t bytes_read = 0;
	*length_read = 0;

	if (!this_instance->partition_info.block_size)
		return -EIO;

	while ((bytes_read < length) && (this_instance->file_pos < this_instance->size)) {

		uint64_t lba = this_instance->file_pos / this_instance->partition_info.block_size;
		size_t offset = this_instance->file_pos % this_instance->partition_info.block_size;

		size_t bytes_remaining_in_block = this_instance->partition_info.block_size - offset;
		size_t bytes_remaining_in_file = this_instance->size - this_instance->file_pos;

		size_t bytes_remaining = length - bytes_read;
		if (bytes_remaining > bytes_remaining_in_file) bytes_remaining = bytes_remaining_in_file;

		size_t requested_len = (bytes_remaining < bytes_remaining_in_block) ?
			bytes_remaining : bytes_remaining_in_block;
		size_t actual_len = 0;

		psa_status_t psa_status = block_store_read(
			this_instance->block_store, 0,
			this_instance->partition_handle,
			lba, offset,
			requested_len,
			(uint8_t*)(buffer + bytes_read),
			&actual_len);

		if (psa_status != PSA_SUCCESS)
			return -EIO;

		bytes_read += actual_len;
		this_instance->file_pos += actual_len;
	}

	*length_read = bytes_read;
	return 0;
}

static int block_volume_write(
	io_entity_t *entity,
	const uintptr_t buffer,
	size_t length,
	size_t *length_written)
{
	struct block_volume *this_instance = (struct block_volume *)entity->info;
	size_t bytes_written = 0;
	*length_written = 0;

	if (!this_instance->partition_info.block_size)
		return -EIO;

	while ((bytes_written < length) && (this_instance->file_pos < this_instance->size)) {

		uint64_t lba = this_instance->file_pos / this_instance->partition_info.block_size;
		size_t offset = this_instance->file_pos % this_instance->partition_info.block_size;

		size_t bytes_remaining_in_block = this_instance->partition_info.block_size - offset;
		size_t bytes_remaining_in_file = this_instance->size - this_instance->file_pos;

		size_t bytes_remaining = length - bytes_written;
		if (bytes_remaining > bytes_remaining_in_file) bytes_remaining = bytes_remaining_in_file;

		size_t requested_len = (bytes_remaining < bytes_remaining_in_block) ?
			bytes_remaining : bytes_remaining_in_block;
		size_t actual_len = 0;

		psa_status_t psa_status = block_store_write(
			this_instance->block_store, 0,
			this_instance->partition_handle,
			lba, offset,
			(uint8_t*)(buffer + bytes_written),
			requested_len,
			&actual_len);

		if (psa_status != PSA_SUCCESS)
			return -EIO;

		bytes_written += actual_len;
		this_instance->file_pos += actual_len;
	}

	*length_written = bytes_written;
	return 0;
}

static int block_volume_erase(uintptr_t context)
{
	struct block_volume *this_instance = (struct block_volume *)context;

	/* Erase the entire open partition. Note that a block_store will clip
	 * the number of blocks to erase to the size of the partition so erasing
	 * a large number of blocks is a safe way to erase the entire partition.
	 */
	psa_status_t psa_status = block_store_erase(
		this_instance->block_store, 0,
		this_instance->partition_handle,
		0, UINT32_MAX);

	if (psa_status != PSA_SUCCESS)
		return -EIO;

	return 0;
}

static int block_volume_get_storage_ids(
	uintptr_t context,
	struct uuid_octets *partition_guid,
	struct uuid_octets *parent_guid)
{
	struct block_volume *this_instance = (struct block_volume *)context;
	struct storage_partition_info partition_info;

	psa_status_t psa_status = block_store_get_partition_info(this_instance->block_store,
		&this_instance->partition_guid,
		&partition_info);

	if (psa_status == PSA_SUCCESS) {

		if (partition_guid)
			*partition_guid = partition_info.partition_guid;

		if (parent_guid)
			*parent_guid = partition_info.parent_guid;

		return 0;
	}

	return -EINVAL;
}
