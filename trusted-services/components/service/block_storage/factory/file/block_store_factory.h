/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FILE_BLOCK_STORE_FACTORY_H
#define FILE_BLOCK_STORE_FACTORY_H

#include "service/block_storage/block_store/block_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A block store factory that constructs a partitioned block store backed
 * by a file block device that provides access to a disk image file.
 * If the disk image contains a GPT, it will be used to configure a set
 * of storage partitions.
 *
 * This factory is intended for deployments where Posix filesystem
 * access is possible with access to a a disk image file.
 */

/**
 * \brief Factory method to create a block_store
 *
 * \return A pointer to the constructed block_store (NULL on failure)
 */
struct block_store *file_block_store_factory_create(void);

/**
 * \brief Destroys a block_store created with block_store_factory_create
 *
 * \param[in] block_store    The block store to destroy
 */
void file_block_store_factory_destroy(struct block_store *block_store);

/**
 * \brief Set the filename for the disk image file
 *
 * \param[in] filename    Disk image filename
 */
void file_block_store_factory_set_filename(const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* FILE_BLOCK_STORE_FACTORY_H */
