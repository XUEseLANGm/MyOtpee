/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef RPMB_BLOCK_STORE_H
#define RPMB_BLOCK_STORE_H

#include "service/rpmb/frontend/rpmb_frontend.h"
#include "service/block_storage/block_store/device/block_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief RPMB block store structure
 *
 * A rpmb_block_store is a block_device that uses the RPMB frontend to provide RPMB based
 * storage
 */
struct rpmb_block_store {
	struct block_device base_block_device;
	struct rpmb_frontend *frontend;
};

/**
 * \brief Initialize a RPMB blockstore
 *
 * \param[in]  block_store	The subject block_store
 * \param[in]  disk_guid	The disk GUID
 * \param[in]  num_blocks	The number of contiguous blocks
 * \param[in]  block_size	Block size in bytes
 *
 * \return Pointer to block_store or NULL on failure
 */
struct block_store *rpmb_block_store_init(struct rpmb_block_store *block_store,
					  const struct uuid_octets *disk_guid,
					  struct rpmb_frontend *frontend);

/**
 * \brief De-initialize a RPMB blockstore
 *
 *  Frees resource allocated during call to ram_block_store_init().
 *
 * \param[in]  block_store  The subject block_store
 */
void rpmb_block_store_deinit(struct rpmb_block_store *block_store);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_BLOCK_STORE_H */
