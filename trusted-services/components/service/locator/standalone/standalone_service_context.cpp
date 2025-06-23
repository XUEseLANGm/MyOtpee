/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "standalone_service_context.h"
#include <cassert>

/* Concrete C service_context methods */
static struct rpc_caller_session *standalone_service_context_open(void *context);
static void standalone_service_context_close(void *context, rpc_caller_session *session_handle);
static void standalone_service_context_relinquish(void *context);


standalone_service_context::standalone_service_context(const char *sn) :
	m_sn(sn),
	m_ref_count(0),
	m_rpc_buffer_size_override(0),
	m_service_context(),
	m_rpc_interface(NULL)
{
	m_service_context.context = this;
	m_service_context.open = standalone_service_context_open;
	m_service_context.close = standalone_service_context_close;
	m_service_context.relinquish = standalone_service_context_relinquish;
}

standalone_service_context::standalone_service_context(
	const char *sn,
	size_t rpc_buffer_size_override) :
	m_sn(sn),
	m_ref_count(0),
	m_rpc_buffer_size_override(rpc_buffer_size_override),
	m_service_context(),
	m_rpc_interface(NULL)
{
	m_service_context.context = this;
	m_service_context.open = standalone_service_context_open;
	m_service_context.close = standalone_service_context_close;
	m_service_context.relinquish = standalone_service_context_relinquish;
}

standalone_service_context::~standalone_service_context()
{

}

void standalone_service_context::init()
{
	assert(m_ref_count >= 0);

	if (!m_ref_count) do_init();
	++m_ref_count;
}

void standalone_service_context::deinit()
{
	assert(m_ref_count > 0);

	--m_ref_count;
	if (!m_ref_count) do_deinit();
}

struct rpc_caller_session *standalone_service_context::open()
{
	rpc_status_t status = RPC_ERROR_INTERNAL;
	struct rpc_caller_interface *caller = NULL;
	struct rpc_caller_session *session = NULL;

	caller = (struct rpc_caller_interface *)calloc(1, sizeof(struct rpc_caller_interface));
	if (!caller)
		return NULL;

	session = (struct rpc_caller_session *)calloc(1, sizeof(struct rpc_caller_session));
	if (!session) {
		free(caller);
		return NULL;
	}

	status = direct_caller_init(caller, m_rpc_interface);
	if (status != RPC_SUCCESS) {
		free(caller);
		free(session);
		return NULL;
	}

	status = rpc_caller_session_open(session, caller, &m_rpc_interface->uuid, 0, 0x8000);
	if (status != RPC_SUCCESS) {
		direct_caller_deinit(caller);
		free(caller);
		free(session);
		return NULL;
	}

	return session;
}

void standalone_service_context::close(rpc_caller_session *session)
{
	rpc_caller_session_close(session);
	direct_caller_deinit(session->caller);
	free(session->caller);
	free(session);
}

const std::string &standalone_service_context::get_service_name() const
{
	return m_sn;
}

struct service_context *standalone_service_context::get_service_context()
{
	return &m_service_context;
}

void standalone_service_context::set_rpc_interface(rpc_service_interface *iface)
{
	m_rpc_interface = iface;
}

static struct rpc_caller_session *standalone_service_context_open(void *context)
{
	standalone_service_context *this_context = reinterpret_cast<standalone_service_context*>(context);

	if (!this_context)
		return NULL;

	return this_context->open();
}

static void standalone_service_context_close(void *context, struct rpc_caller_session *session_handle)
{
	standalone_service_context *this_context = reinterpret_cast<standalone_service_context*>(context);

	if (this_context) {
		this_context->close(session_handle);
	}
}

static void standalone_service_context_relinquish(void *context)
{
	standalone_service_context *this_context = reinterpret_cast<standalone_service_context*>(context);

	if (this_context) {
		this_context->deinit();
	}
}
