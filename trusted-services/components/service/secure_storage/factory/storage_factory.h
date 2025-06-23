/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef STORAGE_FACTORY_H
#define STORAGE_FACTORY_H

#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines a common interface for creating storage backends to
 * decouple a client from the environment and platform specifics
 * of any particular storage backend. Allows new storage backends
 * to be added without impacting client implementations.  The
 * factory method uses PSA storage classifications to allow a
 * client to specify the security characteristics of the backend.
 * How those security characteristics are realized will depend
 * on the secure processing environment and platform.
 *
 * A concrete storage factory may exploit any of the following
 * to influence how the storage backend is constructed:
 *  - Environment and platform specific factory component used in deployment
 *  - Runtime configuration e.g. from Device Tree
 *  - Client specified parameters
 */

/**
 * \brief Security characteristics of created backend
 *
 * Allows a client to request the security characteristics of
 * a constructed backend, using PSA storage classification.  How
 * well a platform meets the requested security characteristics
 * will depend on available hardware features.
 */
enum storage_factory_security_class {

    /**
     * On-die or in-package persistent storage
     * that is exclusively accessible from secure world.
     */
    storage_factory_security_class_INTERNAL_TRUSTED,

    /**
     * External persistent storage with security measures
     * such as encryption, integrity protection and replay
     * protection, based on device root-of-trust trust anchors.
     */
    storage_factory_security_class_PROTECTED
};

/**
 * \brief Factory method to create an initialised storage backend
 *
 * Should use the correseponding destroy method when the storage backend
 * is no longer needed.
 *
 * \param[in] security_class    The requested security class
 *
 * \return A pointer to the initialised storage_backend or NULL on failure
 */
struct storage_backend *storage_factory_create(
                enum storage_factory_security_class security_class);

/**
 * \brief Destroys a created backend
 *
 * Allows a concrete factory to adopt its own allocation scheme for
 * objects used to implement the created backend.
 *
 * \param[in] backend    Storage backend to destroy
  */
void storage_factory_destroy(struct storage_backend *backend);

#ifdef __cplusplus
}
#endif

#endif /* STORAGE_FACTORY_H */
