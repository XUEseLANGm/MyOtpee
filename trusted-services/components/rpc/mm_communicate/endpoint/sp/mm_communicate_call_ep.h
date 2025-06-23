/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MM_COMMUNICATE_CALL_EP_H_
#define MM_COMMUNICATE_CALL_EP_H_

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include "protocols/common/efi/efi_types.h"
#include "ffa_api.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MM_COMMUNICATE_MAX_SERVICE_BINDINGS
#define MM_COMMUNICATE_MAX_SERVICE_BINDINGS				(8)
#endif

/**
 * MM communication specialized call request structure which contains the GUID
 * of the called service and the request/response buffers.
 */
struct mm_service_call_req {
	EFI_GUID *guid;
	struct rpc_buffer req_buf;
	struct rpc_buffer resp_buf;
};

/**
 * MM communicate service definition. The receive function should return an
 * MM communication return code.
 */
struct mm_service_interface {
	void *context;
	int32_t (*receive)(struct mm_service_interface *iface, struct mm_service_call_req *req);
};

/**
 * MM service entry for binding GUIDs to services.
 */
struct mm_service_entry {
	EFI_GUID guid;
	struct mm_service_interface *iface;
};

/**
 * MM endpoint descriptor. It keeps track of the associated services and the
 * MM communication buffer.
 */
struct mm_communicate_ep {
	/* MM communication buffer */
	uint8_t *comm_buffer;
	size_t comm_buffer_size;

	/* Array of binding entries between GUIDs and RPC ifaces. */
	struct mm_service_entry service_table[MM_COMMUNICATE_MAX_SERVICE_BINDINGS];
};

bool mm_communicate_call_ep_init(struct mm_communicate_ep *call_ep, uint8_t *comm_buffer,
				 size_t comm_buffer_size);

void mm_communicate_call_ep_attach_service(struct mm_communicate_ep *call_ep,
					   const EFI_GUID *guid,
					   struct mm_service_interface *iface);

void mm_communicate_call_ep_receive(struct mm_communicate_ep *call_ep,
				    const struct ffa_direct_msg *req_msg,
				    struct ffa_direct_msg *resp_msg);

#ifdef __cplusplus
}
#endif

#endif /* MM_COMMUNICATE_CALL_EP_H_ */
