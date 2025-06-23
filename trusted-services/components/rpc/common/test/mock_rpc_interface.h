/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MOCK_RPC_INTERFACE_H_
#define MOCK_RPC_INTERFACE_H_

#include "../endpoint/rpc_service_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

void mock_rpc_interface_init(void);

void expect_mock_rpc_interface_receive(void *context, const struct rpc_request *req,
				       rpc_status_t result);

rpc_status_t mock_rpc_interface_receive(void *context, struct rpc_request *req);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_RPC_INTERFACE_H_ */
