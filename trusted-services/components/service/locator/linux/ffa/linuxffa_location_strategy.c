/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "linuxffa_location_strategy.h"
#include "linuxffa_service_context.h"
#include "common/uuid/uuid.h"
#include "service/locator/service_name.h"
#include "components/service/attestation/provider/attestation_uuid.h"
#include "components/service/block_storage/provider/block_storage_uuid.h"
#include "components/service/crypto/provider/crypto_uuid.h"
#include "components/service/fwu/provider/fwu_uuid.h"
#include "components/service/rpmb/provider/rpmb_uuid.h"
#include "components/service/secure_storage/frontend/secure_storage_provider/secure_storage_uuid.h"
#include "components/service/test_runner/provider/test_runner_uuid.h"
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>


static struct service_context *query(const char *sn);
static const struct rpc_uuid *suggest_ts_service_uuids(const char *sn);

const struct service_location_strategy *linux_ts_location_strategy(void)
{
	static const struct service_location_strategy strategy = { query };
	return &strategy;
}

static struct service_context *query(const char *sn)
{
	const struct rpc_uuid *service_uuid = NULL;

	/* Determine one or more candidate partition UUIDs from the specified service name. */
	if (!sn_check_authority(sn, "trustedfirmware.org"))
		return NULL;

	service_uuid = suggest_ts_service_uuids(sn);
	if (!service_uuid)
		return NULL;

	return (struct service_context *)linux_ts_service_context_create(service_uuid);
}

/*
 * Returns a list of service UUIDs to identify partitions that could potentially host the requested
 * service.  This mapping is based trustedfirmware.org service UUIDs. There may be multiple UUIDs
 * because of different deployment decisions such as dedicated SP, SP hosting multiple services.
 */
static const struct rpc_uuid *suggest_ts_service_uuids(const char *sn)
{
	static const struct service_to_uuid
	{
		const char *service;
		struct rpc_uuid uuid;
	}
	partition_lookup[] =
	{
		{"crypto-protobuf",             {.uuid = TS_PSA_CRYPTO_PROTOBUF_SERVICE_UUID}},
		{"crypto",                      {.uuid = TS_PSA_CRYPTO_SERVICE_UUID}},
		{"internal-trusted-storage",    {.uuid = TS_PSA_INTERNAL_TRUSTED_STORAGE_UUID}},
		{"protected-storage",           {.uuid = TS_PSA_PROTECTED_STORAGE_UUID}},
		{"test-runner",                 {.uuid = TS_TEST_RUNNER_SERVICE_UUID}},
		{"attestation",                 {.uuid = TS_PSA_ATTESTATION_SERVICE_UUID}},
		{"block-storage",               {.uuid = TS_BLOCK_STORAGE_SERVICE_UUID}},
		{"fwu",                         {.uuid = TS_FWU_SERVICE_UUID}},
		{"rpmb",			{.uuid = TS_RPMB_SERVICE_UUID}},
		{NULL,                          {.uuid = {0}}}
	};

	const struct service_to_uuid *entry = NULL;

	for (entry = &partition_lookup[0]; entry->service != NULL; entry++)
		if (sn_check_service(sn, entry->service))
			return &entry->uuid;

	return NULL;
}
