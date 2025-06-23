/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_SERVICE_CONTEXT_H
#define STANDALONE_SERVICE_CONTEXT_H

#include <cstddef>
#include <service_locator.h>
#include "rpc/common/caller/rpc_caller_session.h"
#include "rpc/common/endpoint/rpc_service_interface.h"
#include "rpc/direct/direct_caller.h"
#include <string>

class standalone_service_context
{
public:
    standalone_service_context(const char *sn);
    standalone_service_context(const char *sn, size_t rpc_buffer_size_override);
    virtual ~standalone_service_context();

    void init();
    void deinit();

    struct rpc_caller_session *open();
    void close(struct rpc_caller_session *session);

    const std::string &get_service_name() const;
    struct service_context *get_service_context();

protected:
    void set_rpc_interface(rpc_service_interface *iface);

    virtual void do_init() {}
    virtual void do_deinit() {}

private:
    std::string m_sn;
    int m_ref_count;
    size_t m_rpc_buffer_size_override;
    struct service_context m_service_context;
    struct rpc_service_interface *m_rpc_interface;
};

#endif /* STANDALONE_SERVICE_CONTEXT_H */
