/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BLOCK_STORAGE_CLIENT_H
#define BLOCK_STORAGE_CLIENT_H

#include "service/common/client/service_client.h"
#include "service/block_storage/block_store/block_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief block_storage_client structure
 *
 * A block_storage_client is a block_store that communicates with a remote block
 * storage service provider. Used when block level storage is handled in a
 * different environment from the client environment.
 */
struct block_storage_client {
	struct block_store base_block_store;
	struct service_client client;
};

/**
 * \brief Initialize a block_storage_client
 *
 * \param[in]  block_storage_client  The subject block_storage_client
 * \param[in]  caller   An rpc_caller for reaching the associated service provider
 *
 * \return Pointer to block_store or NULL on failure
 */
struct block_store *block_storage_client_init(
	struct block_storage_client *block_storage_client,
	struct rpc_caller_session *session);

/**
 * \brief De-initialize a block_storage_client
 *
 *  Frees resource allocated during call to block_storage_client_init().
 *
 * \param[in]  block_storage_client  The subject block_storage_client
 */
void block_storage_client_deinit(
	struct block_storage_client *block_storage_client);


#ifdef __cplusplus
}
#endif

#endif /* BLOCK_STORAGE_CLIENT_H */
