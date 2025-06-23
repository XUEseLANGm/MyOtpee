/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpmb_service_context.h"
#include "service/rpmb/provider/rpmb_uuid.h"
#include <assert.h>

rpmb_service_context::rpmb_service_context(const char *sn) :
	standalone_service_context(sn),
	m_rpmb_provider(),
	m_rpmb_backend(),
	m_rpmb_backend_emulated()
{

}

rpmb_service_context::~rpmb_service_context()
{

}

void rpmb_service_context::do_init()
{
	const struct rpc_uuid service_uuid = {.uuid = TS_RPMB_SERVICE_UUID };

	m_rpmb_backend = rpmb_backend_emulated_init(&m_rpmb_backend_emulated, RPMB_MULT);
	assert(m_rpmb_backend != NULL);

	struct rpc_service_interface *rpmb_service =
		rpmb_provider_init(&m_rpmb_provider, m_rpmb_backend, &service_uuid);
	assert(rpmb_service != NULL);

	standalone_service_context::set_rpc_interface(rpmb_service);
}

void rpmb_service_context::do_deinit()
{
	rpmb_provider_deinit(&m_rpmb_provider);
	m_rpmb_backend = NULL;
	rpmb_backend_emulated_deinit(&m_rpmb_backend_emulated);
}
