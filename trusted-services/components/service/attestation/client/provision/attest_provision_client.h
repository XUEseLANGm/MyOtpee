/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ATTEST_PROVISION_CLIENT_H
#define ATTEST_PROVISION_CLIENT_H

#include <psa/error.h>
#include "rpc_caller_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Initialises the singleton attestion provisioning client
 *
 * Implements the provisioning client API defined in attest_provision.h
 *
 * @param[in]  rpc_caller RPC caller instance
 *
 * @return     A status indicating the success/failure of the operation
 */
psa_status_t attest_provision_client_init(struct rpc_caller_session *session);

/**
 * @brief      De-initialises the singleton attestion provisioning client
 *
 */
void attest_provision_client_deinit(void);

/**
 * @brief      Return the most recent RPC status
 *
 * May be used to obtain information about an RPC error that resulted
 * in an API operation failure
 *
 * @return     Most recent RPC operation status
 */
int attest_provision_client_rpc_status(void);


#ifdef __cplusplus
}
#endif

#endif /* ATTEST_PROVISION_CLIENT_H */
