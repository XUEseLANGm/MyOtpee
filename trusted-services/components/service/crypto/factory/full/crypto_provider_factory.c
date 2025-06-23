/*
 * Copyright (c) 2021-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <service/crypto/factory/crypto_provider_factory.h>
#include <service/crypto/provider/crypto_provider.h>
#include <service/crypto/provider/serializer/protobuf/pb_crypto_provider_serializer.h>
#include <service/crypto/provider/serializer/packed-c/packedc_crypto_provider_serializer.h>
#include <service/crypto/provider/extension/hash/hash_provider.h>
#include <service/crypto/provider/extension/hash/serializer/packed-c/packedc_hash_provider_serializer.h>
#include <service/crypto/provider/extension/cipher/cipher_provider.h>
#include <service/crypto/provider/extension/cipher/serializer/packed-c/packedc_cipher_provider_serializer.h>
#include <service/crypto/provider/extension/key_derivation/key_derivation_provider.h>
#include <service/crypto/provider/extension/key_derivation/serializer/packed-c/packedc_key_derivation_provider_serializer.h>
#include <service/crypto/provider/extension/mac/mac_provider.h>
#include <service/crypto/provider/extension/mac/serializer/packed-c/packedc_mac_provider_serializer.h>
#include <service/crypto/provider/extension/aead/aead_provider.h>
#include <service/crypto/provider/extension/aead/serializer/packed-c/packedc_aead_provider_serializer.h>

/**
 * A crypto provider factory that constucts a crypto provider
 * that is extended to support the full set of crypto operations.
 * This factory is only capable of constructing a single service
 * provider instance.
 */

static struct full_crypto_provider
{
	struct crypto_provider crypto_provider;
	struct crypto_provider crypto_provider_protobuf;
	struct hash_provider hash_provider;
	struct cipher_provider cipher_provider;
	struct key_derivation_provider key_derivation_provider;
	struct mac_provider mac_provider;
	struct aead_provider aead_provider;
} instance;

struct crypto_provider *crypto_provider_factory_create(void)
{
	/**
	 * Initialize the core crypto provider
	 */
	crypto_provider_init(&instance.crypto_provider, TS_RPC_ENCODING_PACKED_C,
			     packedc_crypto_provider_serializer_instance());

	/**
	 * Extend with hash operations
	 */
	hash_provider_init(&instance.hash_provider);

	hash_provider_register_serializer(&instance.hash_provider,
		TS_RPC_ENCODING_PACKED_C, packedc_hash_provider_serializer_instance());

	crypto_provider_extend(&instance.crypto_provider,
		&instance.hash_provider.base_provider);

	/**
	 *  Extend with symmetric cipher operations
	 * */
	cipher_provider_init(&instance.cipher_provider);

	cipher_provider_register_serializer(&instance.cipher_provider,
		TS_RPC_ENCODING_PACKED_C, packedc_cipher_provider_serializer_instance());

	crypto_provider_extend(&instance.crypto_provider,
		&instance.cipher_provider.base_provider);

	/**
	 *  Extend with key derivation operations
	 */
	key_derivation_provider_init(&instance.key_derivation_provider);

	key_derivation_provider_register_serializer(&instance.key_derivation_provider,
		TS_RPC_ENCODING_PACKED_C,
		packedc_key_derivation_provider_serializer_instance());

	crypto_provider_extend(&instance.crypto_provider,
		&instance.key_derivation_provider.base_provider);

	/**
	 * Extend with mac operations
	 */
	mac_provider_init(&instance.mac_provider);

	mac_provider_register_serializer(&instance.mac_provider,
		TS_RPC_ENCODING_PACKED_C, packedc_mac_provider_serializer_instance());

	crypto_provider_extend(&instance.crypto_provider,
		&instance.mac_provider.base_provider);

	/**
	 * Extend with aead operations
	 */
	aead_provider_init(&instance.aead_provider);

	aead_provider_register_serializer(&instance.aead_provider,
		TS_RPC_ENCODING_PACKED_C, packedc_aead_provider_serializer_instance());

	crypto_provider_extend(&instance.crypto_provider,
		&instance.aead_provider.base_provider);

	return &instance.crypto_provider;
}

struct crypto_provider *crypto_protobuf_provider_factory_create(void)
{
	crypto_provider_init(&instance.crypto_provider_protobuf, TS_RPC_ENCODING_PROTOBUF,
			     pb_crypto_provider_serializer_instance());

	return &instance.crypto_provider_protobuf;
}

/**
 * \brief Destroys a created crypto provider
 *
 * \param[in] provider    The crypto provider to destroy
  */
void crypto_provider_factory_destroy(struct crypto_provider *provider)
{
	(void)provider;
	crypto_provider_deinit(&instance.crypto_provider);
	hash_provider_deinit(&instance.hash_provider);
	cipher_provider_deinit(&instance.cipher_provider);
	key_derivation_provider_deinit(&instance.key_derivation_provider);
	mac_provider_deinit(&instance.mac_provider);
}
