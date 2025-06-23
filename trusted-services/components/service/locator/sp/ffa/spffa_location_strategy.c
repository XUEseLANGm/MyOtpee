/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>
#include "spffa_location_strategy.h"
#include "spffa_service_context.h"
#include "sp_discovery.h"
#include <common/uuid/uuid.h>
#include <service/locator/service_name.h>
#include "components/rpc/ts_rpc/caller/sp/ts_rpc_caller_sp.h"
#include <trace.h>

static struct service_context *query(const char *sn);

const struct service_location_strategy *sp_ts_location_strategy(void)
{
	static const struct service_location_strategy strategy = { query };
	return &strategy;
}

/**
 * This service location strategy is intended for locating other service
 * endpoints reachable via FFA from within a client secure partition where
 * associated service endpoints are explicitly defined by configuration data.
 * The service to locate is specified by a service name that consists of a
 * UUID and an optional instance number.  If present, the instance number
 * is treated as the destination RPC interface id.  If not specified,
 * an interface id of zero is assumed.
 */
static struct service_context *query(const char *sn)
{
	struct uuid_canonical uuid = { 0 };
	struct rpc_uuid service_uuid = { 0 };
	struct sp_ts_service_context *new_context = NULL;

	/* This strategy only locates endpoints reachable via FFA */
	if (!sn_check_authority(sn, "ffa")) {
		EMSG("failed to check authority");
		return NULL;
	}

	if (!sn_read_service(sn, uuid.characters, sizeof(uuid.characters)) ||
	    !uuid_is_valid(uuid.characters)) {
		EMSG("invalid uuid");
		return NULL;
	}

	uuid_parse_to_octets(uuid.characters, service_uuid.uuid, sizeof(service_uuid.uuid));

	new_context = spffa_service_context_create(&service_uuid);
	if (!new_context) {
		EMSG("context create failed");
		return NULL;
	}

	return &new_context->service_context;
}
