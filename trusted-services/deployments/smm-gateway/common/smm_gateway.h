/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SMM_GATEWAY_H
#define SMM_GATEWAY_H

#include "rpc/common/endpoint/rpc_service_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Factory method for constructing an smm_gateway
 *
 * A common factory method for constructing an smm_gateway. The gateway
 * presents a set of UEFI SMM service interfaces via the returned
 * rpc_interface. An environment specific initializer calls this function
 * to construct the environment independent smm_gateway provider.
 *
 * @param[in] owner_id The id of the owning security domain (e.g. partition id)
 *
 * \return An rpc_interface or NULL on failure
 */
struct rpc_service_interface *smm_gateway_create(uint32_t owner_id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SMM_GATEWAY_H */
