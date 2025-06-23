/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef CRYPTO_PROVIDER_FACTORY_H
#define CRYPTO_PROVIDER_FACTORY_H

#include <service/crypto/provider/crypto_provider.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines a common interface for creating crypto providers.
 * A concrete factory will construct base crypto providers,
 * extended with any extra capabilities needed for a
 * deployment.
 */

/**
 * \brief Factory method to create an initialised crypto provider.
 *
 * \return A pointer to the initialised crypto provider or NULL on failure
 */
struct crypto_provider *crypto_provider_factory_create(void);

struct crypto_provider *crypto_protobuf_provider_factory_create(void);

/**
 * \brief Destroys a created crypto provider
 *
 * \param[in] provider    The crypto provider to destroy
  */
void crypto_provider_factory_destroy(struct crypto_provider *provider);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_PROVIDER_FACTORY_H */
