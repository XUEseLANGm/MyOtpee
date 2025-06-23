/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BLOCK_DEVICE_H
#define BLOCK_DEVICE_H

#include "service/block_storage/block_store/block_store.h"
#include "service/block_storage/block_store/storage_partition.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief block_device structure
 *
 * A block_device is a block_store that provides block storage in some way. A
 * block_device specializes the base block_store to provide a common base for
 * block storage devices such as flash drivers. Because any block_device realizes
 * the common block_store interface, it may be used in any situation where the
 * upper layer uses the block_store interface.  A block_device exposes a single
 * storage partition that represents the physical storage presented by
 * the block_device. The block size and number of blocks will have been discovered
 * in some way or will have been provided via configuration data.
 */
struct block_device
{
	struct block_store base_block_store;
	struct storage_partition storage_partition;
};

/**
 * \brief Initialize a block_device
 *
 * If configuration parameters are known at initialisation, they may be
 * provided to configure the block device. If not, pass zero values for
 * unknown configuration parameters.
 *
 * \param[in]  block_device  	The subject block_device
 * \param[in]  disk_guid   		The disk GUID (can be NULL)
 * \param[in]  num_blocks       The number of contiguous blocks
 * \param[in]  block_size       Block size in bytes
 *
 * \return Pointer to the base block_store or NULL on failure
 */
struct block_store *block_device_init(
	struct block_device *block_device,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size);

/**
 * \brief De-initialize a block_device
 *
 * \param[in]  block_device  The subject block_device
 */
void block_device_deinit(
	struct block_device *block_device);

/**
 * \brief Configure a block_device
 *
 * Configure an initialised block_device. Configuration parameters are assumed
 * to have been sanity checked based on knowledge of the concrete block_device.
 *
 * \param[in]  block_device  	The subject block_device
 * \param[in]  disk_guid   		The disk GUID (can be NULL)
 * \param[in]  num_blocks       The number of contiguous blocks
 * \param[in]  block_size       Block size in bytes
 */
void block_device_configure(
	struct block_device *block_device,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size);

/**
 * \brief Check if access is permitted
 *
 *  Called by concrete block devices to check if a client is permitted access.
 *
 * \param[in]  block_device  The subject block_device
 * \param[in]  client_id     The requesting client ID
 * \param[in]  handle        The handle presented by the client
 *
 * \return PSA_SUCCESS if access permitted
 */
psa_status_t block_device_check_access_permitted(
	const struct block_device *block_device,
	uint32_t client_id,
	storage_partition_handle_t handle);

/**
 * \brief Get information about the block device
 *
 *  Called by concrete block devices to get information about the storage devices
 *
 * \param[in]  block_device    The subject block_device
 * \param[in]  partition_guid  The requested partition GUID
 * \param[out] info            The retrieved information about the storage device
 *
 * \return PSA_SUCCESS on success
 */
psa_status_t block_device_get_partition_info(
	struct block_device *block_device,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info);

/**
 * \brief Open the block device
 *
 *  Called by concrete block devices to obtain a handle to use the block device
 *
 * \param[in]  block_device    The subject block_device
 * \param[in]  client_id       The requesting client ID
 * \param[in]  partition_guid  The requested partition GUID
 * \param[out] handle          The handle to use for device access operations
 *
 * \return PSA_SUCCESS on success
 */
psa_status_t block_device_open(
	struct block_device *block_device,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle);

/**
 * \brief Close the block device
 *
 * \param[in]  block_device    The subject block_device
 * \param[in]  client_id       The requesting client ID
 * \param[in]  handle          The handle obtained on open
 *
 * \return PSA_SUCCESS on success
 */
psa_status_t block_device_close(
	struct block_device *block_device,
	uint32_t client_id,
	storage_partition_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_DEVICE_H */
