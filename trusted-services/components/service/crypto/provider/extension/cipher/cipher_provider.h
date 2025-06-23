/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CIPHER_PROVIDER_H
#define CIPHER_PROVIDER_H

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include <service/common/provider/service_provider.h>
#include <service/crypto/provider/extension/cipher/serializer/cipher_provider_serializer.h>
#include <service/crypto/provider/crypto_context_pool.h>
#include <protocols/rpc/common/packed-c/encoding.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A service provider that can be used to add symmetric cipher operations to the core
 * crypto provider.
 */
struct cipher_provider
{
	struct service_provider base_provider;
	struct crypto_context_pool context_pool;
	const struct cipher_provider_serializer *serializers[TS_RPC_ENCODING_LIMIT];
};

/*
 * Initializes an instance of the cipher service provider.
 */
void cipher_provider_init(struct cipher_provider *context);

/*
 * When operation of the provider is no longer required, this function
 * frees any resource used by the previously initialized provider instance.
 */
void cipher_provider_deinit(struct cipher_provider *context);

/*
 * Register a serializer for supportng a particular parameter encoding.
 */
void cipher_provider_register_serializer(struct cipher_provider *context,
	unsigned int encoding, const struct cipher_provider_serializer *serializer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CIPHER_PROVIDER_H */
