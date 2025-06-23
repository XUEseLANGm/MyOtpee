/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef SEMIHOSTING_BLOCK_STORE_FACTORY_H
#define SEMIHOSTING_BLOCK_STORE_FACTORY_H

#include "service/block_storage/block_store/block_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A block store factory that constructs a partitioned block store backed
 * by a semihosting block device that provides access to a disk image file
 * residing in the host's filesystem. If the disk image contains a GPT, it
 * will be used to configure a set of storage partitions.
 *
 * Semihosting is an Arm debug facility that enables device software to
 * communicate with the host. Can be used in emulated environments (FVP &
 * QEMU) and with real hardware with a suitable debugger.
 */

/**
 * \brief Factory method to create a block_store
 *
 * \return A pointer to the constructed block_store (NULL on failure)
 */
struct block_store *semihosting_block_store_factory_create(void);

/**
 * \brief Destroys a block_store created with block_store_factory_create
 *
 * \param[in] block_store    The block store to destroy
 */
void semihosting_block_store_factory_destroy(struct block_store *block_store);

#ifdef __cplusplus
}
#endif

#endif /* SEMIHOSTING_BLOCK_STORE_FACTORY_H */
