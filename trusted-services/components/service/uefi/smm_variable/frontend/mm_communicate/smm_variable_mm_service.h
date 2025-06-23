/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef SMM_VARIABLE_MM_SERVICE_H_
#define SMM_VARIABLE_MM_SERVICE_H_

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include "components/rpc/mm_communicate/endpoint/sp/mm_communicate_call_ep.h"
#include "protocols/service/smm_variable/smm_variable_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * MM service interface implementation for parsing SMM variable requests and
 * forwarding them to an RPC interface.
 */
struct smm_variable_mm_service {
	struct mm_service_interface mm_service;
	struct rpc_service_interface *iface;
};

struct mm_service_interface *smm_variable_mm_service_init(struct smm_variable_mm_service *service,
							  struct rpc_service_interface *iface);

#ifdef __cplusplus
}
#endif

#endif /* SMM_VARIABLE_MM_SERVICE_H_ */
