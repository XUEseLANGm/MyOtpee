/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fwu_service_context.h"

struct rpc_service_interface *fwu_service_context::m_provider_iface = NULL;

fwu_service_context::fwu_service_context(const char *sn)
	: standalone_service_context(sn)
{
}

fwu_service_context::~fwu_service_context()
{
}

void fwu_service_context::set_provider(struct rpc_service_interface *iface)
{
	m_provider_iface = iface;
}

void fwu_service_context::do_init()
{
	standalone_service_context::set_rpc_interface(m_provider_iface);
}

void fwu_service_context::do_deinit()
{
	set_provider(NULL);
}

void fwu_service_context_set_provider(struct rpc_service_interface *iface)
{
	fwu_service_context::set_provider(iface);
}