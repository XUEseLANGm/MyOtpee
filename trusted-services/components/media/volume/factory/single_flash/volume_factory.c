/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "media/volume/factory/volume_factory.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "media/disk/guid.h"
#include "media/volume/block_volume/block_volume.h"
#include "service/block_storage/block_store/block_store.h"
#include "service/block_storage/factory/block_store_factory.h"
#include "trace.h"

/**
 * A volume factory for single flash deployments where underlying block-level
 * access is provided by a block_store object. The block_store used is provided
 * by the block_store_factory selected for the deployment. This could construct
 * any suitable block_store.
 */
static struct block_store *single_block_store;

int volume_factory_init(struct uuid_octets *device_uuids, size_t device_uuids_size,
			size_t *num_device_uuids)
{
	assert(device_uuids || !device_uuids_size);
	assert(num_device_uuids);

	*num_device_uuids = 0;
	single_block_store = block_store_factory_create();

	if (!single_block_store) {
		EMSG("Failed to construct block_store");
		return -EIO;
	}

	if (device_uuids_size > 0) {
		struct storage_partition_info device_info;
		struct uuid_octets uuid;

		/* Query for GPT partition to get info about the parent device */
		uuid_guid_octets_from_canonical(&uuid, DISK_GUID_UNIQUE_PARTITION_DISK_HEADER);

		psa_status_t psa_status =
			block_store_get_partition_info(single_block_store, &uuid, &device_info);

		if (psa_status == PSA_SUCCESS)
			device_uuids[0] = device_info.parent_guid;
		else
			memset(&device_uuids[0], 0, sizeof(struct uuid_octets));

		*num_device_uuids = 1;
	}

	return 0;
}

void volume_factory_deinit(void)
{
	block_store_factory_destroy(single_block_store);
	single_block_store = NULL;
}

struct volume *volume_factory_create_volume(const struct uuid_octets *partition_uuid,
					    const struct uuid_octets *device_uuid)
{
	struct volume *product = NULL;

	assert(single_block_store);

	/* This factory assumes that all volumes are backed by a single block device */
	(void)device_uuid;

	struct block_volume *block_volume =
		(struct block_volume *)malloc(sizeof(struct block_volume));

	if (block_volume) {
		int status = block_volume_init(block_volume, single_block_store, partition_uuid,
					       &product);

		if (status) {
			EMSG("Failed to init block volume: %d", status);
			product = NULL;
			free(block_volume);
		}
	} else {
		EMSG("Failed to alloc block volume");
	}

	return product;
}

void volume_factory_destroy_volume(struct volume *volume)
{
	if (volume && volume->io_spec)
		free((void *)volume->io_spec);
}
