/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CRYPTO_PARTITION_H
#define CRYPTO_PARTITION_H

#include "service/crypto/backend/crypto_backend.h"
#include <stdint.h>

/**
 * Concerned with partitioning of the crypto service backed key store to protect
 * keys and key store resource. Key partitioning for stored keys is handled by
 * associating keys with a namespace that reflects the owner.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Returns the key id namespace associated with a client id
 *
 * \param client_id	The uniform identifier for the client
 * \return The associated key id namespace
 */
key_id_namespace_t crypto_partition_get_namespace(uint32_t client_id);

/**
 * \brief Returns a namespaced key id
 *
 * \param client_id	The uniform identifier for the client
 * \param key_id	The key id
 * \return The namespaced key id
 */
namespaced_key_id_t crypto_partition_get_namespaced_key_id(uint32_t client_id, psa_key_id_t key_id);

/**
 * \brief Associate a key with an owner
 *
 * \param attributes	Key attributes object
 * \param client_id	The uniform identifier for the client
 */
void crypto_partition_bind_to_owner(psa_key_attributes_t *attributes, uint32_t client_id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CRYPTO_PARTITION_H */
