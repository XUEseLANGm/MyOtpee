/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SECURE_STORAGE_PROVIDER_H
#define SECURE_STORAGE_PROVIDER_H

#include "service/common/provider/service_provider.h"
#include "service/secure_storage/backend/storage_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      A secure storage service provider
 *
 * Implements an RPC interface that realizes the secure storage service.
 * Acts as a storage frontend that may be paired with any storage backend.
 */
struct secure_storage_provider {
	struct service_provider base_provider;
	struct storage_backend *backend;
};

struct rpc_service_interface *secure_storage_provider_init(struct secure_storage_provider *context,
							   struct storage_backend *backend,
							   const struct rpc_uuid *service_uuid);

void secure_storage_provider_deinit(struct secure_storage_provider *context);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_STORAGE_PROVIDER_H */
