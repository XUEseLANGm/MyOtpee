/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STUB_CRYPTO_BACKEND_H
#define STUB_CRYPTO_BACKEND_H

#include <psa/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize the stub crypto backend
 *
 * Initializes a crypto backend that uses the psa API client with a
 * stub backend caller to realize the PSA crypto API used by the crypto
 * service proviser.
 *
 * \return PSA_SUCCESS if backend initialized successfully
 */
psa_status_t stub_crypto_backend_init(void);

/**
 * \brief Clean-up to free any resource used by the crypto backend
 */
void stub_crypto_backend_deinit(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* STUB_CRYPTO_BACKEND_H */
