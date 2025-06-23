/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include "partitioned_block_store.h"

static psa_status_t find_by_partition_guid(
	struct partitioned_block_store *partitioned_block_store,
	const struct uuid_octets *partition_guid,
	size_t *index)
{
	psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
	bool try_again = false;

	do {

		for (size_t i = 0; i < partitioned_block_store->num_partitions; i++) {

			if (storage_partition_is_guid_matched(
				&partitioned_block_store->storage_partition[i],
				partition_guid)) {

				*index = i;
				status = PSA_SUCCESS;
				break;
			}
		}

		/* Search again if on-demand configuration was performed */
		try_again =
			(status != PSA_SUCCESS) &&
			!try_again &&
			partitioned_block_store->config_listener &&
			partitioned_block_store->config_listener(
				partitioned_block_store,
				partition_guid,
				&partitioned_block_store->back_store_info);

	} while (try_again);

	return status;
}

static psa_status_t validate_partition_request(
	const struct partitioned_block_store *partitioned_block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	const struct storage_partition **partition)
{
	size_t index = (size_t)handle;

	if (index >= PARTITIONED_BLOCK_STORE_MAX_PARTITIONS)
		return PSA_ERROR_INVALID_ARGUMENT;

	const struct storage_partition *requested_partition =
		&partitioned_block_store->storage_partition[index];

	if (!storage_partition_is_access_permitted(requested_partition, client_id))
		return PSA_ERROR_NOT_PERMITTED;

	/* Access permitted to requested partition */
	*partition = requested_partition;

	return PSA_SUCCESS;
}

static psa_status_t partitioned_block_store_get_partition_info(void *context,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info)
{
	struct partitioned_block_store *partitioned_block_store =
		(struct partitioned_block_store*)context;

	size_t partition_index = 0;
	psa_status_t status = find_by_partition_guid(
		partitioned_block_store,
		partition_guid,
		&partition_index);

	if (status == PSA_SUCCESS) {

		const struct storage_partition *partition =
			&partitioned_block_store->storage_partition[partition_index];

		info->block_size = partition->block_size;
		info->num_blocks = partition->num_blocks;
		info->partition_guid = partition->partition_guid;
		info->parent_guid = partitioned_block_store->back_store_info.partition_guid;
	}

	return status;
}

static psa_status_t partitioned_block_store_open(void *context,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle)
{
	struct partitioned_block_store *partitioned_block_store =
		(struct partitioned_block_store*)context;

	size_t partition_index = 0;
	psa_status_t status = find_by_partition_guid(
		partitioned_block_store,
		partition_guid,
		&partition_index);

	if (status == PSA_SUCCESS) {

		struct storage_partition *partition =
			&partitioned_block_store->storage_partition[partition_index];

		if (storage_partition_is_open_permitted(partition,
				client_id,
				partitioned_block_store->authorizer)) {

			*handle = (storage_partition_handle_t)partition_index;
		}
		else {

			status = PSA_ERROR_NOT_PERMITTED;
		}
	}

	return status;
}

static psa_status_t partitioned_block_store_close(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	const struct partitioned_block_store *partitioned_block_store =
		(struct partitioned_block_store*)context;

	const struct storage_partition *partition = NULL;

	psa_status_t status = validate_partition_request(
		partitioned_block_store,
		client_id,
		handle,
		&partition);

	return status;
}

static psa_status_t partitioned_block_store_read(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	size_t buffer_size,
	uint8_t *buffer,
	size_t *data_len)
{
	const struct partitioned_block_store *partitioned_block_store =
		(struct partitioned_block_store*)context;

	const struct storage_partition *partition = NULL;

	psa_status_t status = validate_partition_request(
		partitioned_block_store,
		client_id,
		handle,
		&partition);

	if (status == PSA_SUCCESS) {

		if (storage_partition_is_lba_legal(partition, lba)) {

			size_t clipped_read_len = storage_partition_clip_length(
				partition,
				lba, offset,
				buffer_size);

			/* Read from underlying back store */
			status = block_store_read(
				partitioned_block_store->back_store,
				partitioned_block_store->local_client_id,
				partitioned_block_store->back_store_handle,
				partition->base_lba + lba,
				offset,
				clipped_read_len,
				buffer,
				data_len);
		}
		else {

			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

static psa_status_t partitioned_block_store_write(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	const uint8_t *data,
	size_t data_len,
	size_t *num_written)
{
	const struct partitioned_block_store *partitioned_block_store =
		(struct partitioned_block_store*)context;

	const struct storage_partition *partition = NULL;

	psa_status_t status = validate_partition_request(
		partitioned_block_store,
		client_id,
		handle,
		&partition);

	if (status == PSA_SUCCESS) {

		if (storage_partition_is_lba_legal(partition, lba)) {

			size_t clipped_data_len = storage_partition_clip_length(
				partition, lba, offset,
				data_len);

			/* Write to underlying back store */
			status = block_store_write(
				partitioned_block_store->back_store,
				partitioned_block_store->local_client_id,
				partitioned_block_store->back_store_handle,
				partition->base_lba + lba,
				offset,
				data,
				clipped_data_len,
				num_written);
		}
		else {

			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

static psa_status_t partitioned_block_store_erase(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t begin_lba,
	size_t num_blocks)
{
	const struct partitioned_block_store *partitioned_block_store =
		(struct partitioned_block_store*)context;

	const struct storage_partition *partition = NULL;

	psa_status_t status = validate_partition_request(
		partitioned_block_store,
		client_id,
		handle,
		&partition);

	if (status == PSA_SUCCESS) {

		if (storage_partition_is_lba_legal(partition, begin_lba)) {

			size_t clipped_num_blocks = storage_partition_clip_num_blocks(
				partition, begin_lba,
				num_blocks);

			status = block_store_erase(
				partitioned_block_store->back_store,
				partitioned_block_store->local_client_id,
				partitioned_block_store->back_store_handle,
				partition->base_lba + begin_lba,
				clipped_num_blocks);
		}
		else {

			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

struct block_store *partitioned_block_store_init(
	struct partitioned_block_store *partitioned_block_store,
	uint32_t local_client_id,
	const struct uuid_octets *back_store_guid,
	struct block_store *back_store,
	storage_partition_authorizer authorizer)
{
	/* Define concrete block store interface */
	static const struct block_store_interface interface =
	{
		partitioned_block_store_get_partition_info,
		partitioned_block_store_open,
		partitioned_block_store_close,
		partitioned_block_store_read,
		partitioned_block_store_write,
		partitioned_block_store_erase
	};

	/* Initialize base block_store */
	partitioned_block_store->base_block_store.context = partitioned_block_store;
	partitioned_block_store->base_block_store.interface = &interface;

	/* Note the local client ID - this corresponds to the local environment */
	partitioned_block_store->local_client_id = local_client_id;

	/* Note the environment specific authorizer function */
	partitioned_block_store->authorizer = authorizer;

	/* Default to no config listener */
	partitioned_block_store->config_listener = NULL;

	/* Initially no partitions. */
	partitioned_block_store->num_partitions = 0;

	/* Stack over provided back store */
	partitioned_block_store->back_store = back_store;

	/* Get information about the underlying back store */
	struct storage_partition_info info;
	psa_status_t status = block_store_get_partition_info(partitioned_block_store->back_store,
		back_store_guid,
		&info);

	if (status != PSA_SUCCESS)
		return NULL;

	partitioned_block_store->back_store_info = info;

	/* Open underlying block store */
	status = block_store_open(partitioned_block_store->back_store,
		partitioned_block_store->local_client_id,
		back_store_guid,
		&partitioned_block_store->back_store_handle);

	if (status != PSA_SUCCESS)
		return NULL;

	return &partitioned_block_store->base_block_store;
}

void partitioned_block_store_deinit(
	struct partitioned_block_store *partitioned_block_store)
{
	block_store_close(partitioned_block_store->back_store,
		partitioned_block_store->local_client_id,
		partitioned_block_store->back_store_handle);

	for (size_t i = 0; i < partitioned_block_store->num_partitions; ++i)
		storage_partition_deinit(&partitioned_block_store->storage_partition[i]);
}

void partitioned_block_store_attach_config_listener(
	struct partitioned_block_store *partitioned_block_store,
	partition_config_listener config_listener)
{
	partitioned_block_store->config_listener = config_listener;
}

bool partitioned_block_store_add_partition(
	struct partitioned_block_store *partitioned_block_store,
	const struct uuid_octets *partition_guid,
	uint64_t starting_lba,
	uint64_t ending_lba,
	uint64_t attributes,
	const char *owner)
{
	(void)attributes;
	(void)owner;

	if (partitioned_block_store->num_partitions >= PARTITIONED_BLOCK_STORE_MAX_PARTITIONS)
		return false;

	/* Check partition blocks lie within limits of the back store */
	if ((starting_lba > ending_lba) ||
		(ending_lba >= partitioned_block_store->back_store_info.num_blocks))
		return false;

	/* Initialise a new storage_partition structure */
	struct storage_partition *storage_partition =
		&partitioned_block_store->storage_partition[partitioned_block_store->num_partitions];

	storage_partition_init(
		storage_partition,
		partition_guid,
		ending_lba - starting_lba + 1,
		partitioned_block_store->back_store_info.block_size);

	storage_partition->base_lba = starting_lba;

	++partitioned_block_store->num_partitions;

	return true;
}

const struct storage_partition_info *partitioned_block_store_get_back_store_info(
	const struct partitioned_block_store *partitioned_block_store)
{
	return &partitioned_block_store->back_store_info;
}
