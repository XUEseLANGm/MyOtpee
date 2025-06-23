/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_PROVIDER_H_
#define RPMB_PROVIDER_H_

#include "service/common/provider/service_provider.h"
#include "service/rpmb/backend/rpmb_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief RPMB service provider
 */
struct rpmb_provider {
	struct service_provider base_provider;
	struct rpmb_backend *backend;
};

/**
 * \brief Initializes the RPMB service provider
 *
 * \param context[in]		Provider context
 * \param backend[in]		RPMB backend
 * \param service_uuid[in]	Service UUID
 * \return struct rpc_service_interface* RPC service interface or NULL on error
 */
struct rpc_service_interface *rpmb_provider_init(struct rpmb_provider *context,
						 struct rpmb_backend *backend,
						 const struct rpc_uuid *service_uuid);

/**
 * \brief Deinitializes the RPMB service provider
 *
 * \param context[in]	Provider context
 */
void rpmb_provider_deinit(struct rpmb_provider *context);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_PROVIDER_H_ */
