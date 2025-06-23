/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpc_caller_session.h"
#include <openamp_messenger_api.h>

typedef void *psa_ipc_call_handle;

void *psa_ipc_phys_to_virt(void *context, void *pa);
void *psa_ipc_virt_to_phys(void *context, void *va);

rpc_status_t psa_ipc_caller_init(struct rpc_caller_interface *rpc_caller);
rpc_status_t psa_ipc_caller_deinit(struct rpc_caller_interface *rpc_caller);

psa_ipc_call_handle psa_ipc_caller_begin(struct rpc_caller_interface *caller,
					 uint8_t **request_buffer,
					 size_t request_length);

rpc_status_t psa_ipc_caller_invoke(psa_ipc_call_handle handle, uint32_t opcode,
				       uint8_t **response_buffer,
				       size_t *response_length);

rpc_status_t psa_ipc_caller_end(psa_ipc_call_handle handle);