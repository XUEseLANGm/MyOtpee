/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "crypto_client.h"
#include <protocols/rpc/common/packed-c/status.h>

crypto_client::crypto_client() :
	m_client()
{
	service_client_init(&m_client, NULL);
}

crypto_client::crypto_client(struct rpc_caller_session *session) :
	m_client()
{
	service_client_init(&m_client, session);
}

crypto_client::~crypto_client()
{
	service_client_deinit(&m_client);
}

void crypto_client::set_caller(struct rpc_caller_session *session)
{
	m_client.session = session;
}

int crypto_client::err_rpc_status() const
{
	return m_client.rpc_status;
}

struct service_info crypto_client::get_service_info() const
{
	return m_client.service_info;
}
