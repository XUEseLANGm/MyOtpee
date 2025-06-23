/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef CLIENT_BLOCK_STORE_FACTORY_H
#define CLIENT_BLOCK_STORE_FACTORY_H

#include "service/block_storage/block_store/block_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A block store factory that constructs a block_storage_client
 * (which is a block_store specialization). The constructed client
 * establishes a session with the discovered block storage service
 * provider.
 */

/**
 * \brief Factory method to create a block_store
 *
 * \param[in] sn    Service name identifying block storage provider
 * \return A pointer to the constructed block_store (NULL on failure)
 */
struct block_store *client_block_store_factory_create(const char *sn);

/**
 * \brief Destroys a block_store created with block_store_factory_create
 *
 * \param[in] block_store    The block store to destroy
 */
void client_block_store_factory_destroy(struct block_store *block_store);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_BLOCK_STORE_FACTORY_H */
