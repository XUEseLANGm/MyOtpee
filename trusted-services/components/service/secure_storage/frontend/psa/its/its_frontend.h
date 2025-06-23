/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_ITS_FRONTEND_H
#define PSA_ITS_FRONTEND_H

#include <psa/error.h>
#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Assignes a concrete rpc caller to the ITS frontend and initialises
 *             the singleton ITS frontend instance
 *
 * Provides an implementation of the PSA ITS API as a storage frontend.  Any
 * suitable storage backend may be used.
 *
 * @param[in]  backend Storage backend to use
 *
 * @return     A status indicating the success/failure of the operation
 */
psa_status_t psa_its_frontend_init(struct storage_backend *backend);

#ifdef __cplusplus
}
#endif

#endif /* PSA_ITS_FRONTEND_H */
