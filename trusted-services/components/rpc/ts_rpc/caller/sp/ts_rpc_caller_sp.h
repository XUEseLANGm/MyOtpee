/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_RPC_CALLER_SP_H
#define TS_RPC_CALLER_SP_H

#include "rpc_status.h"
#include "rpc_uuid.h"
#include "sp_discovery.h"
#include <common/uuid/uuid.h>
#include "components/rpc/ts_rpc/common/ts_rpc_abi.h"
#include "components/rpc/common/caller/rpc_caller.h"
#include "util.h"

/* Protocol version*/
#define TS_RPC_PROTOCOL_VERSION		(1)

#ifdef __cplusplus
extern "C" {
#endif

rpc_status_t ts_rpc_caller_sp_init(struct rpc_caller_interface *rpc_caller);

rpc_status_t ts_rpc_caller_sp_deinit(struct rpc_caller_interface *rpc_caller);

#ifdef __cplusplus
}
#endif

#endif /* TS_RPC_CALLER_SP_H */
