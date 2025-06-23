/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DUMMY_CALLER
#define DUMMY_CALLER

#include "rpc_caller.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An rpc_caller that is used to return a suitable permanent status
 * code if an attempt is made to invoke a remote method where an
 * end-to-end rpc session has failed to be established.  Intended
 * to be used when a session with a real rpc endpoint cant't be
 * established but a client doesn't wish to treat the condition
 * as a fatal error.
 */

rpc_status_t dummy_caller_init(struct rpc_caller_interface *caller, rpc_status_t rpc_status,
			       service_status_t service_status);
rpc_status_t dummy_caller_deinit(struct rpc_caller_interface *caller);

#ifdef __cplusplus
}
#endif

#endif /* DUMMY_CALLER */
