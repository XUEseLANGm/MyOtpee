/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MBEDTLS_PSA_CRYPTO_BACKEND_H
#define MBEDTLS_PSA_CRYPTO_BACKEND_H

/**
 * A crypto backend that uses a configuration of mbedtls to provide the
 * backend interface used by a crypto provider.  The build configuration
 * enables namespacing of key ids.
 */

#ifdef MBEDTLS_PSA_CRYPTO_H
#include MBEDTLS_PSA_CRYPTO_H
#endif

#include <mbedtls/build_info.h>
#include <mbedtls/error.h>
#include <mbedtls/pkcs7.h>
#include <mbedtls/x509_crt.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mbedtls supports key id namespacing via the mbedtls_svc_key_id_t
 * type that combines a key id with an owner id.
 */
typedef mbedtls_svc_key_id_t namespaced_key_id_t;
#define NAMESPACED_KEY_ID_INIT MBEDTLS_SVC_KEY_ID_INIT

/**
 * Map to the mbedtls owner id type for the namespace.
 */
typedef mbedtls_key_owner_id_t key_id_namespace_t;
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
	*namespaced_key_id = mbedtls_svc_key_id_make(key_namespace, key_id);
}

/**
 * \brief Get the key id from a namespaced_key_id_t
 *
 * \param namespaced_key_id	Namespaced key id
 * \return Key id without namespace
 */
static inline psa_key_id_t namespaced_key_id_get_key_id(namespaced_key_id_t namespaced_key_id)
{
	return MBEDTLS_SVC_KEY_ID_GET_KEY_ID(namespaced_key_id);
}

/**
 * \brief Set the key id namespace associated with a key attributes object
 *
 * The default implementation discards the namespace
 *
 * \param attributes 	Key attributes object
 * \param key_namespace		Key id namespace
 */
static inline void namespaced_key_id_set_namespace(psa_key_attributes_t *attributes,
						   key_id_namespace_t key_namespace)
{
	mbedtls_set_key_owner_id(attributes, key_namespace);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MBEDTLS_PSA_CRYPTO_BACKEND_H */
