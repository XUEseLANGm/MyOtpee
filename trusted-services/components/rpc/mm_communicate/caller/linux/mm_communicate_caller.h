/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MM_COMMUNICATE_CALLER_H
#define MM_COMMUNICATE_CALLER_H

#include <stdbool.h>
#include <common/uuid/uuid.h>
#include <protocols/common/efi/efi_types.h>
#include "rpc_caller.h"
#include "mm_communicate_serializer.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An RPC caller for Linux user-space clients that uses the MM_COMMUNICATE
 * protocol for calling UEFI SMM service endpoints.
 */
RPC_CALLER_EXPORTED
rpc_status_t mm_communicate_caller_init(struct rpc_caller_interface *caller,
					const char *ffa_device_path);

RPC_CALLER_EXPORTED
rpc_status_t mm_communicate_caller_deinit(struct rpc_caller_interface *caller);

#ifdef __cplusplus
}
#endif

#endif /* MM_COMMUNICATE_CALLER_H */
