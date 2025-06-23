/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef NULL_BLOCK_STORE_H
#define NULL_BLOCK_STORE_H

#include "service/block_storage/block_store/device/block_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief null_block_store structure
 *
 * A null_block_store is a block_device that will ignore write operations and
 * always return zero for read blocks. Because there is no storage, a null_block_store
 * can be any size and support any block size. It is intended to be used as a placeholder
 * block device during integration.
 */
struct null_block_store
{
	struct block_device base_block_device;
};

/**
 * \brief Initialize a null_block_store
 *
 * \param[in]  null_block_store  The subject null_block_store
 * \param[in]  disk_guid   		The disk GUID (nil uuid for any)
 * \param[in]  num_blocks       The number of contiguous blocks
 * \param[in]  block_size       Block size in bytes
 *
 * \return Pointer to block_store or NULL on failure
 */
struct block_store *null_block_store_init(
	struct null_block_store *null_block_store,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size);

/**
 * \brief De-initialize a null_block_store
 *
 * \param[in]  null_block_store  The subject null_block_store
 */
void null_block_store_deinit(
	struct null_block_store *null_block_store);

#ifdef __cplusplus
}
#endif

#endif /* NULL_BLOCK_STORE_H */
