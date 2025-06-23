/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SMM_VARIABLE_PROVIDER_H
#define SMM_VARIABLE_PROVIDER_H

#include "rpc/common/endpoint/rpc_service_interface.h"
#include "service/common/provider/service_provider.h"
#include "service/uefi/smm_variable/backend/uefi_variable_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The smm_variable_provider is a service provider that implements an RPC interface
 * for an instance of the smm_variable service.
 */
struct smm_variable_provider {
	struct service_provider base_provider;
	struct uefi_variable_store variable_store;
};

/**
 * \brief Initialize an instance of the smm_variable service provider
 *
 * Initializes an smm_variable service provider.  Returns an rpc_interface that should
 * be associated with a suitable rpc endpoint.  Storage backends for NV and volatile
 * stores are assumed to be deployment specific and are passed as initialization
 * parameters.
 *
 * @param[in] context The instance to initialize
 * @param[in] owner_id The id of the owning security domain (e.g. partition id)
 * @param[in] max_variables The maximum number of stored variables
 * @param[in] persistent_store The persistent storage backend to use
 * @param[in] volatile_store The volatile storage backend to use
 *
 * \return An rpc_interface or NULL on failure
 */
struct rpc_service_interface *smm_variable_provider_init(struct smm_variable_provider *context,
							 uint32_t owner_id, size_t max_variables,
							 struct storage_backend *persistent_store,
							 struct storage_backend *volatile_store);

/**
 * \brief Cleans up when the instance is no longer needed
 *
 * \param[in] context   The instance to de-initialize
 */
void smm_variable_provider_deinit(struct smm_variable_provider *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SMM_VARIABLE_PROVIDER_H */
