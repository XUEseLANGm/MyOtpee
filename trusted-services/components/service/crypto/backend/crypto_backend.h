/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

/**
 * The crypto backend implements the backend interface used by a crypto
 * provider.  By default, the backend interface is the standard psa
 * crypto api with additional functions to provide a common interface
 * for partitioning the keystore into separate namespaces.  Alternative
 * backends can provide their own version of the interface with overridden
 * types and keystore namespacing functions.
 */
#ifdef ALTERNATIVE_CRYPTO_BACKEND
#include ALTERNATIVE_CRYPTO_BACKEND
#else
#include "default_psa_crypto_backend.h"
#endif

#endif /* CRYPTO_BACKEND_H */
