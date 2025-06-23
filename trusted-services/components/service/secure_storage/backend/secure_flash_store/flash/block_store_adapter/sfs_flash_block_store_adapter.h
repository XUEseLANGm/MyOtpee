/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file sfs_flash_block_store_adapter.h
 *
 * \brief Adapts the sfs flash interface to block_store interface
 *
 * Can be used to access a storage partition exposed by a concrete
 * block_store. An example use is to interface to a block_store that
 * acts as a client to the block storage service.
 */

#ifndef __SFS_FLASH_BLOCK_STORE_ADAPTER_H__
#define __SFS_FLASH_BLOCK_STORE_ADAPTER_H__

#include <stdint.h>
#include "../sfs_flash.h"
#include "service/block_storage/block_store/block_store.h"
#include "common/uuid/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief sfs_flash_block_store_adapter structure
 */
struct sfs_flash_block_store_adapter
{
	struct sfs_flash_info_t flash_info;
	struct block_store *block_store;
	storage_partition_handle_t partition_handle;
	uint32_t client_id;
	size_t blocks_per_flash_block;
};

/**
 * \brief Initialize the block store adapter
 *
 * On success, the underlying block store is opened and the flash_info
 * structure in initialised, based on the info queried from the block
 * store.
 *
 * \param[in] context      This adapter context
 * \param[in] client_id    The client id for the environment
 * \param[in] block_store  The associated block store
 * \param[in] partition_guid The storage partition to use
 * \param[in] min_flash_block_size Minimum sfs block size
 * \param[in] max_num_files	An sfs configuration parameter
 * \param[out] flash_info  The sfs flash interface structure
 *
 * \return PSA_SUCCESS when successful
 */
psa_status_t sfs_flash_block_store_adapter_init(
	struct sfs_flash_block_store_adapter *context,
	uint32_t client_id,
	struct block_store *block_store,
	const struct uuid_octets *partition_guid,
	size_t min_flash_block_size,
	size_t max_num_files,
	const struct sfs_flash_info_t **flash_info);

/**
 * \brief Deinitialize the block store adapter
 *
 * \param[in] context      This adapter context
 *
* \return PSA_SUCCESS when successful
 */
psa_status_t sfs_flash_block_store_adapter_deinit(
	struct sfs_flash_block_store_adapter *context);

#ifdef __cplusplus
}
#endif

#endif /* __SFS_FLASH_BLOCK_STORE_ADAPTER_H__ */
