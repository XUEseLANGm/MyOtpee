/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_IAT_CLIENT_H
#define PSA_IAT_CLIENT_H

#include <psa/error.h>
#include "rpc_caller_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Initialises the singleton IAT client
 *
 * The IAT client provides an implementation of the PSA Attestation API.
 * This API may be used by client applications to request attestion
 * tokens.
 *
 * @param[in]  rpc_caller RPC caller instance
 *
 * @return     A status indicating the success/failure of the operation
 */
psa_status_t psa_iat_client_init(struct rpc_caller_session *session);

/**
 * @brief      De-initialises the singleton IAT client
 *
 */
void psa_iat_client_deinit(void);

/**
 * @brief      Return the most recent RPC status
 *
 * May be used to obtain information about an RPC error that resulted
 * in an API operation failure
 *
 * @return     Most recent RPC operation status
 */
int psa_iat_client_rpc_status(void);


#ifdef __cplusplus
}
#endif

#endif /* PSA_IAT_CLIENT_H */
