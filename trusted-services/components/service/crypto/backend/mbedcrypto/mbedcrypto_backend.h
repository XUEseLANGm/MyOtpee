/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MBEDCRYPTO_BACKEND_H
#define MBEDCRYPTO_BACKEND_H

#include <stdbool.h>
#include <psa/error.h>
#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize the mbedcrypto based backend
 *
 * Initializes a crypto backend that uses the mbedcrypto library built by
 * MbedTLS to realize the PSA crypto API used by the crypto service proviser.
 *
 * \param[in] storage_backend   The storage backend to use for persistent keys
 * \param[in] trng_instance_num  The TRNG hardware instance number to use
 *
 * \return PSA_SUCCESS if backend initialized successfully
 */
psa_status_t mbedcrypto_backend_init(struct storage_backend *storage_backend,
						int trng_instance_num);

/**
 * \brief Clean-up to free any resource used by the backend
 */
void mbedcrypto_backend_deinit(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MBEDCRYPTO_BACKEND_H */
