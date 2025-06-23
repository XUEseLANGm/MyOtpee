/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_RPMB_SERVICE_CONTEXT_H
#define STANDALONE_RPMB_SERVICE_CONTEXT_H

#include "service/locator/standalone/standalone_service_context.h"
#include "service/rpmb/backend/emulated/rpmb_backend_emulated.h"
#include "service/rpmb/provider/rpmb_provider.h"

class rpmb_service_context : public standalone_service_context
{
public:
	rpmb_service_context(const char *sn);
	virtual ~rpmb_service_context();

private:

	void do_init();
	void do_deinit();

	/* Set emulated RPMB size to 2 * 128kB */
	static const uint16_t RPMB_MULT = 2;

	struct rpmb_provider m_rpmb_provider;
	struct rpmb_backend *m_rpmb_backend;
	struct rpmb_backend_emulated m_rpmb_backend_emulated;
};

#endif /* STANDALONE_RPMB_SERVICE_CONTEXT_H */
