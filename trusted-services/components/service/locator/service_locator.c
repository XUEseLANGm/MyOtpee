/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "service_locator.h"
#include "service_name.h"
#include <assert.h>
#include <stddef.h>

#define SERVICE_LOCATOR_MAX_STATEGIES       (8)

/*
 * The singleton service_locator object.
 */
static struct service_locator
{
	unsigned int num_strategies;
	const struct service_location_strategy *strategies[SERVICE_LOCATOR_MAX_STATEGIES];

} service_locator_instance = { .num_strategies = 0 };


void service_locator_init(void)
{
	if (service_locator_instance.num_strategies == 0) service_locator_envinit();
}

void service_locator_register_strategy(const struct service_location_strategy *strategy)
{
	assert(service_locator_instance.num_strategies < SERVICE_LOCATOR_MAX_STATEGIES);

	if (service_locator_instance.num_strategies < SERVICE_LOCATOR_MAX_STATEGIES) {

		service_locator_instance.strategies[service_locator_instance.num_strategies] = strategy;
		++service_locator_instance.num_strategies;
	}
}

struct service_context *service_locator_query(const char *sn)
{
	struct service_context *located_context = NULL;
	unsigned int index = 0;

	if (sn_is_valid(sn)) {

		while (!located_context && (index < service_locator_instance.num_strategies)) {

			located_context = service_locator_instance.strategies[index]->query(sn);
			++index;
		}
	}

	return located_context;
}

struct rpc_caller_session *service_context_open(struct service_context *s)
{
	return s->open(s->context);
}

void service_context_close(struct service_context *s, struct rpc_caller_session *session)
{
	s->close(s->context, session);
}

void service_context_relinquish(struct service_context *s)
{
	s->relinquish(s->context);
}
