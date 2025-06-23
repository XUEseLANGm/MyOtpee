/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef RAM_BLOCK_STORE_H
#define RAM_BLOCK_STORE_H

#include "service/block_storage/block_store/device/block_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief ram_block_store structure
 *
 * A ram_block_store is a block_device that uses normal memory for block storage.
 * It presents a single storage partition with the capacity specified at initialization.
 * The ram_block_store is intended to be used in test integrations where a real
 * NV block_store is either not available or is not needed.
 */
struct ram_block_store
{
	struct block_device base_block_device;
	uint8_t *ram_back_store;
};

/**
 * \brief Initialize a ram_block_store
 *
 * \param[in]  ram_block_store  The subject ram_block_store
 * \param[in]  disk_guid   		The disk GUID
 * \param[in]  num_blocks       The number of contiguous blocks
 * \param[in]  block_size       Block size in bytes
 *
 * \return Pointer to block_store or NULL on failure
 */
struct block_store *ram_block_store_init(
	struct ram_block_store *ram_block_store,
	const struct uuid_octets *disk_guid,
	size_t num_blocks,
	size_t block_size);

/**
 * \brief De-initialize a ram_block_store
 *
 *  Frees resource allocated during call to ram_block_store_init().
 *
 * \param[in]  ram_block_store  The subject ram_block_store
 */
void ram_block_store_deinit(
	struct ram_block_store *ram_block_store);

/**
 * \brief Modify the ram back store
 *
 *  Test support function to allow the ram back store to be modified.
 *
 * \param[in]  ram_block_store  The subject ram_block_store
 * \param[in]  offset   Byte offset from start of store
 * \param[in]  data		Data to write
 * \param[in]  data_len Length of data to write
 *
 * \return PSA_SUCCESS on success
 */
psa_status_t ram_block_store_modify(
	struct ram_block_store *ram_block_store,
	size_t offset,
	const uint8_t *data,
	size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* RAM_BLOCK_STORE_H */
