/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "standalone_location_strategy.h"
#include "standalone_service_registry.h"
#include "standalone_service_context.h"

static struct service_context *query(const char *sn)
{
    standalone_service_registry *registry = standalone_service_registry::instance();
    standalone_service_context *query_result = registry->query(sn);

    if (!query_result)
        return NULL;

    return query_result->get_service_context();
}

const struct service_location_strategy *standalone_location_strategy(void)
{
    static const struct service_location_strategy strategy = { query };
    return &strategy;
}
