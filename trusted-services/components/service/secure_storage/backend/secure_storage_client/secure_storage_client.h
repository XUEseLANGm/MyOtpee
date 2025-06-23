/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SECURE_STORAGE_CLIENT_H
#define SECURE_STORAGE_CLIENT_H

#include <service/secure_storage/backend/storage_backend.h>
#include <service/common/client/service_client.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Secure storage client instance
 */
struct secure_storage_client
{
    struct storage_backend backend;
    struct service_client client;
};

/**
 * @brief      Initialize a secure storage client
 *
 * A secure storage client is a storage backend that makes RPC calls
 * to a remote secure storage provider.
 *
 * @param[in]  context    Instance data
 * @param[in]  rpc_caller RPC caller instance
 *
 *
 * @return     Pointer to inialized storage backend or NULL on failure
 */
struct storage_backend *secure_storage_client_init(struct secure_storage_client *context,
						   struct rpc_caller_session *session);

/**
 * @brief      Deinitialize a secure storage client
 *
 * @param[in]  context   Instance data
 */
void secure_storage_client_deinit(struct secure_storage_client *context);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_STORAGE_CLIENT_H */
