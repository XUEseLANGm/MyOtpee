/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPC_STATUS_H
#define RPC_STATUS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Used for returning the status of an RPC transaction. These values indicating the result of the
 * RPC layer operations. Service level result must be handled in a service specific way.
 */

typedef int32_t rpc_status_t;

#define RPC_SUCCESS			(0)
#define RPC_ERROR_INTERNAL		(-1)
#define RPC_ERROR_INVALID_VALUE		(-2)
#define RPC_ERROR_NOT_FOUND		(-3)
#define RPC_ERROR_INVALID_STATE		(-4)
#define RPC_ERROR_TRANSPORT_LAYER	(-5)
#define RPC_ERROR_INVALID_REQUEST_BODY	(-6)
#define RPC_ERROR_INVALID_RESPONSE_BODY	(-7)
#define RPC_ERROR_RESOURCE_FAILURE	(-8)

typedef int64_t service_status_t;

#ifdef __cplusplus
}
#endif

#endif /* RPC_STATUS_H */
