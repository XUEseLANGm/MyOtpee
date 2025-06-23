/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HASH_PROVIDER_H
#define HASH_PROVIDER_H

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include <service/common/provider/service_provider.h>
#include <service/crypto/provider/extension/hash/serializer/hash_provider_serializer.h>
#include <service/crypto/provider/crypto_context_pool.h>
#include <protocols/rpc/common/packed-c/encoding.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A service provider that can be used to add hash operations to the core
 * crypto provider.
 */
struct hash_provider
{
	struct service_provider base_provider;
	struct crypto_context_pool context_pool;
	const struct hash_provider_serializer *serializers[TS_RPC_ENCODING_LIMIT];
};

/*
 * Initializes an instance of the hash service provider.
 */
void hash_provider_init(struct hash_provider *context);

/*
 * When operation of the provider is no longer required, this function
 * frees any resource used by the previously initialized provider instance.
 */
void hash_provider_deinit(struct hash_provider *context);

/*
 * Register a serializer for supportng a particular parameter encoding.
 */
void hash_provider_register_serializer(struct hash_provider *context,
	unsigned int encoding, const struct hash_provider_serializer *serializer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HASH_PROVIDER_H */
