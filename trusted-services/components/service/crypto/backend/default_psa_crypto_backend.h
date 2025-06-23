/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEFAULT_PSA_CRYPTO_BACKEND_H
#define DEFAULT_PSA_CRYPTO_BACKEND_H

#include <stdint.h>

/**
 * Provides the common crypto backend interface, based on the psa crypto
 * API. To accommodate backend specific overrides to API types, a
 * backend may provide its own API definitions.
 */
#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Crypto frontends that support some kind of key id namespacing, should
 * use this type for key ids. Namespacing allows for partitioning of
 * the key id namespace. The nature of the partitioning is up to a
 * crypto frontend. Note that a backend may override this typedef to
 * suite the backend's handling of namespaces.
 */
typedef psa_key_id_t namespaced_key_id_t;
#define NAMESPACED_KEY_ID_INIT PSA_KEY_ID_NULL

/**
 * An overridable type for a key id namespace.
 */
typedef int32_t key_id_namespace_t;
#define KEY_ID_NAMESPACE_INIT 0

/**
 * \brief Initialize a namespaced key id
 *
 * This default implementation just discards the namespace.
 *
 * \param namespaced_key_id	The object to initialize
 * \param key_namespace		The namespace
 * \param key_id		The key id
 */
static inline void namespaced_key_id_init(namespaced_key_id_t *namespaced_key_id,
					  key_id_namespace_t key_namespace,
					  psa_key_id_t key_id)
{
	(void)key_namespace;
	*namespaced_key_id = key_id;
}

/**
 * \brief Get the key id from a namespaced_key_id_t
 *
 * \param namespaced_key_id	Namespaced key id
 * \return Key id without namespace
 */
static inline psa_key_id_t namespaced_key_id_get_key_id(namespaced_key_id_t namespaced_key_id)
{
	return namespaced_key_id;
}

/**
 * \brief Set the key id namespace associated with a key attributes object
 *
 * The default implementation discards the namespace
 *
 * \param attributes		Key attributes object
 * \param key_namespace		Key id namespace
 */
static inline void namespaced_key_id_set_namespace(psa_key_attributes_t *attributes,
						   key_id_namespace_t key_namespace)
{
	(void)attributes;
	(void)key_namespace;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DEFAULT_PSA_CRYPTO_BACKEND_H */
