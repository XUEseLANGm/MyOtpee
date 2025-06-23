/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_FWU_SERVICE_CONTEXT_H
#define STANDALONE_FWU_SERVICE_CONTEXT_H

#include "service/locator/standalone/standalone_service_context.h"

class fwu_service_context : public standalone_service_context {
public:
	explicit fwu_service_context(const char *sn);
	virtual ~fwu_service_context();

	static void set_provider(struct rpc_service_interface *iface);

private:
	void do_init();
	void do_deinit();

	static struct rpc_service_interface *m_provider_iface;
};

/*
 * Export function to set the service provider
 */
#ifdef EXPORT_PUBLIC_INTERFACE_FWU_SERVICE_CONTEXT
#define FWU_SERVICE_CONTEXT_EXPORTED __attribute__((__visibility__("default")))
#else
#define FWU_SERVICE_CONTEXT_EXPORTED
#endif

FWU_SERVICE_CONTEXT_EXPORTED void fwu_service_context_set_provider(struct rpc_service_interface *iface);

#endif /* STANDALONE_FWU_SERVICE_CONTEXT_H */
