/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include "mm_communicate_location_strategy.h"
#include "mm_communicate_service_context.h"
#include <common/uuid/uuid.h>
#include <service/locator/service_name.h>
#include <rpc/mm_communicate/caller/linux/mm_communicate_caller.h>
#include <protocols/service/smm_variable/smm_variable_proto.h>

/* Structure to define the location of an smm service */
struct smm_service_location
{
	struct uuid_canonical uuid;
	uint16_t partition_id;
	EFI_GUID svc_guid;
};

/* Structure to map a service name to FFA and MM Communicate labels */
struct smm_service_label
{
	const char *service;
	const char *uuid;
	EFI_GUID svc_guid;
};

bool find_candidate_location(const char *sn, struct smm_service_location *location)
{
	static const struct smm_service_label service_lookup[] =
	{
		{
			.service = "smm-variable",
			.uuid = SMM_VARIABLE_CANONICAL_GUID,
			.svc_guid = SMM_VARIABLE_GUID
		},
		{
			/* Terminator */
			.service = NULL
		}
	};

	bool found = false;
	const struct smm_service_label *entry = &service_lookup[0];

	while (entry->service) {

		if (sn_check_service(sn, entry->service)) {

			/* Found a match */
			memcpy(location->uuid.characters,
				entry->uuid,
				UUID_CANONICAL_FORM_LEN + 1);

			location->svc_guid = entry->svc_guid;

			found = true;
			break;
		}

		++entry;
	}

	return found;
}

static struct service_context *query(const char *sn)
{
	struct smm_service_location location = { 0 };
	struct mm_communicate_service_context *new_context = NULL;
	static const char *dev_path = "/sys/kernel/debug/arm_ffa_user";


	if (!sn_check_authority(sn, "trustedfirmware.org"))
		return NULL;

	if (!find_candidate_location(sn, &location))
		return NULL;

	new_context = mm_communicate_service_context_create(
			dev_path,
			location.partition_id,
			&location.svc_guid);
	if (!new_context)
		return NULL;

	return &new_context->service_context;
}

const struct service_location_strategy *mm_communicate_location_strategy(void)
{
	static const struct service_location_strategy strategy = { query };
	return &strategy;
}
