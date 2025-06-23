/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_CLIENT_H_
#define RPMB_CLIENT_H_

#include "components/service/rpmb/backend/rpmb_backend.h"
#include "components/rpc/common/caller/rpc_caller_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief RPMB client
 *
 * The RPMB client provides and RPMB backend via accessing a remove backend through RPC.
 */
struct rpmb_client {
	struct rpmb_backend backend;
	struct rpc_caller_session *session;
};

/**
 * \brief Initialize RPMB client
 *
 * \param context[in]	RPMB client context
 * \param session[in]	RPC caller session
 * \return struct rpmb_backend* RPMB backend or NULL on error
 */
struct rpmb_backend *rpmb_client_init(struct rpmb_client *context,
				      struct rpc_caller_session *session);

/**
 * \brief Deinitialize RPMB client
 *
 * \param context[in]	RPMB client context
 */
void rpmb_client_deinit(struct rpmb_client *context);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_CLIENT_H_ */
