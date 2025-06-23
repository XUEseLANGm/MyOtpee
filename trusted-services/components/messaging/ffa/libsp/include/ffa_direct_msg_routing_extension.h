/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LIBSP_INCLUDE_FFA_DIRECT_MSG_ROUTING_EXTENSION_H_
#define LIBSP_INCLUDE_FFA_DIRECT_MSG_ROUTING_EXTENSION_H_

#include "ffa_api_types.h"
#include "sp_api_defines.h"
#include "sp_api_types.h"

#ifdef __cplusplus
extern "C" {
#endif

ffa_result ffa_direct_msg_routing_ext_wait_post_hook(struct ffa_direct_msg *req);

ffa_result ffa_direct_msg_routing_ext_req_pre_hook(struct ffa_direct_msg *req);
ffa_result ffa_direct_msg_routing_ext_req_post_hook(struct ffa_direct_msg *resp);
void ffa_direct_msg_routing_ext_req_error_hook(void);

ffa_result ffa_direct_msg_routing_ext_resp_pre_hook(struct ffa_direct_msg *resp);
ffa_result ffa_direct_msg_routing_ext_resp_post_hook(struct ffa_direct_msg *req);
void ffa_direct_msg_routing_ext_resp_error_hook(void);

ffa_result ffa_direct_msg_routing_ext_rc_req_pre_hook(struct ffa_direct_msg *req);
ffa_result ffa_direct_msg_routing_ext_rc_req_post_hook(struct ffa_direct_msg *resp);
void ffa_direct_msg_routing_ext_rc_req_error_hook(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_INCLUDE_FFA_DIRECT_MSG_ROUTING_EXTENSION_H_ */
