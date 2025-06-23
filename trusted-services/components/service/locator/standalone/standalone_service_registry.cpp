/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "standalone_service_registry.h"

standalone_service_registry::standalone_service_registry() :
    m_service_instances()
{

}

standalone_service_registry::~standalone_service_registry()
{

}

standalone_service_registry *standalone_service_registry::instance()
{
    static standalone_service_registry singleton_instance;
    return &singleton_instance;
}

void standalone_service_registry::regsiter_service_instance(standalone_service_context *service_context)
{
    size_t index;

    if (find_context_index(service_context->get_service_name().c_str(), &index)) {

        m_service_instances[index] = service_context;
    }
    else {

        m_service_instances.push_back(service_context);
    }
}

standalone_service_context *standalone_service_registry::deregsiter_service_instance(const char *sn)
{
    size_t index;
    standalone_service_context *context = NULL;

    if (find_context_index(sn, &index)) {

        context = m_service_instances[index];
        m_service_instances.erase(m_service_instances.begin() + index);
    }

    return context;
}

standalone_service_context *standalone_service_registry::query(const char *sn)
{
    size_t index;
    standalone_service_context *context = NULL;

    if (find_context_index(sn, &index)) {

        context = m_service_instances[index];
        context->init();
    }

    return context;
}

bool standalone_service_registry::find_context_index(const char *sn, size_t *index) const
{
    bool found = false;

    for (size_t i = 0; !found && i < m_service_instances.size(); i++) {

        if (m_service_instances[i]->get_service_name().compare(sn) == 0) {

            *index = i;
            found = true;
        }
    }

    return found;
}