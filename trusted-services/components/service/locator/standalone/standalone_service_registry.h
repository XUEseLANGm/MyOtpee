/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_SERVICE_REGISTRY_H
#define STANDALONE_SERVICE_REGISTRY_H

#include "standalone_service_context.h"
#include <vector>

/*
 * The standalone_service_registry supports a set of standalone
 * service instances that are deployed as part of a standalone exectable
 * or library.  A standalone deployment of service providers should only
 * be used for test and development.  Because service provider instances
 * are running within the same execution context as the client, a
 * standalone deployment offers no isolation from the client.
 */
class standalone_service_registry
{
public:
    standalone_service_registry();
    virtual ~standalone_service_registry();

    static standalone_service_registry *instance();

    void regsiter_service_instance(standalone_service_context *service_context);
    standalone_service_context *deregsiter_service_instance(const char *sn);

    standalone_service_context *query(const char *sn);

private:
    bool find_context_index(const char *sn, size_t *index) const;

    std::vector<standalone_service_context*> m_service_instances;
};

#endif /* STANDALONE_SERVICE_REGISTRY_H */