/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_BLOCK_VOLUME_H
#define MEDIA_BLOCK_VOLUME_H

#include <common/uuid/uuid.h>
#include <media/volume/volume.h>
#include <service/block_storage/block_store/block_store.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Provides a concrete volume that presents a block storage partition
 * as a single volume. Access to the underlying storage is handled by an associated
 * block_store. The block_store could be any concrete block_store.
 */
struct block_volume {
	struct volume base_volume;
	size_t file_pos;
	size_t size;
	struct block_store *block_store;
	struct uuid_octets partition_guid;
	storage_partition_handle_t partition_handle;
	struct storage_partition_info partition_info;
};

/**
 * @brief  Initialize an block_volume instance
 *
 * @param[in] this_instance    The subject block_volume
 * @param[in] block_store      The associated block_store
 * @param[in] partition_guid   The partition GUID
 * @param[out] volume	       The base volume
 *
 * @return 0 on success
 */
int block_volume_init(
	struct block_volume *this_instance,
	struct block_store *block_store,
	const struct uuid_octets *partition_guid,
	struct volume **volume);

/**
 * @brief  De-initialize an block_volume instance
 *
 * @param[in] this_instance    The subject block_volume
 */
void block_volume_deinit(
	struct block_volume *this_instance);

/**
 * @brief  Set the partition GUID
 *
 * Modifies the partition GUID. This will be used to identify the target
 * storage partition on a subsequent call to io_dev_open.
 *
 * @param[in] this_instance    The subject block_volume
 * @param[in] partition_guid   The partition GUID
 */
void block_volume_set_partition_guid(
	struct block_volume *this_instance,
	const struct uuid_octets *partition_guid);

#ifdef __cplusplus
}
#endif

#endif /* MEDIA_BLOCK_VOLUME_H */
