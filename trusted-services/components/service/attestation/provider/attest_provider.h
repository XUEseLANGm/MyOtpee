/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ATTEST_PROVIDER_H
#define ATTEST_PROVIDER_H

#include "rpc/common/endpoint/rpc_service_interface.h"
#include "rpc/common/caller/rpc_caller.h"
#include "service/common/provider/service_provider.h"
#include "service/attestation/provider/serializer/attest_provider_serializer.h"
#include "service/attestation/key_mngr/attest_key_mngr.h"
#include "protocols/rpc/common/packed-c/encoding.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The attest_provider is a service provider that implements an RPC interface
 * for an instance of the attestation service.
 */
struct attest_provider
{
	struct service_provider base_provider;
	const struct attest_provider_serializer *serializer;
};

/**
 * \brief Initialize an instance of the service provider
 *
 * Initializes a an attestation service provider.  Returns an rpc_interface
 * that should be associated with a suitable rpc endpoint.
 *
 * \param[in] context   The instance to initialize
 *
 * \return An rpc_interface or NULL on failure
 */
struct rpc_service_interface *attest_provider_init(struct attest_provider *context);

/**
 * \brief Cleans up when the instance is no longer needed
 *
 * \param[in] context   The instance to de-initialize
 */
void attest_provider_deinit(struct attest_provider *context);

/**
 * \brief Register a protocol serializer
 *
 * \param[in] context     The instance
 * \param[in] encoding    Serialization encoding e.g. packed-c
 * \param[in] serializer  A concrete serializer
 */
void attest_provider_register_serializer(struct attest_provider *context,
	const struct attest_provider_serializer *serializer);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ATTEST_PROVIDER_H */
