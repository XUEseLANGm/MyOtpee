/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PS_FRONTEND_H
#define PS_FRONTEND_H

#include <psa/error.h>
#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Assigns a concrete storage backend to the PS frontend and initialises
 *             the singleton PS frontend instance
 *
 * Provides an implementation of the PSA PS API as a storage frontend.  Any
 * suitable storage backend may be used.
 *
 * @param[in]  backend Storage backend to use
 *
 * @return     A status indicating the success/failure of the operation
 */
psa_status_t psa_ps_frontend_init(struct storage_backend *backend);

#ifdef __cplusplus
}
#endif

#endif /* PS_FRONTEND_H */
