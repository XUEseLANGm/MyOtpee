/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef KEY_DERIVATION_PROVIDER_H
#define KEY_DERIVATION_PROVIDER_H

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include <service/common/provider/service_provider.h>
#include <service/crypto/provider/extension/key_derivation/serializer/key_derivation_provider_serializer.h>
#include <service/crypto/provider/crypto_context_pool.h>
#include <protocols/rpc/common/packed-c/encoding.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A service provider that can be used to add key_derivation operations to the core
 * crypto provider.
 */
struct key_derivation_provider
{
	struct service_provider base_provider;
	struct crypto_context_pool context_pool;
	const struct key_derivation_provider_serializer *serializers[TS_RPC_ENCODING_LIMIT];
};

/*
 * Initializes an instance of the key_derivation service provider.
 */
void key_derivation_provider_init(struct key_derivation_provider *context);

/*
 * When operation of the provider is no longer required, this function
 * frees any resource used by the previously initialized provider instance.
 */
void key_derivation_provider_deinit(struct key_derivation_provider *context);

/*
 * Register a serializer for supportng a particular parameter encoding.
 */
void key_derivation_provider_register_serializer(struct key_derivation_provider *context,
	unsigned int encoding, const struct key_derivation_provider_serializer *serializer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KEY_DERIVATION_PROVIDER_H */
