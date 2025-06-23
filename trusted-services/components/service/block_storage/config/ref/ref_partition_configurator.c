/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include <stddef.h>
#include "ref_partition_configurator.h"

bool ref_partition_configure(struct partitioned_block_store *subject)
{
	struct uuid_octets guid;

	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_1_GUID);
	bool is_success = partitioned_block_store_add_partition(
		subject,
		&guid,
		REF_PARTITION_1_STARTING_LBA,
		REF_PARTITION_1_ENDING_LBA,
		0, NULL);

	if (!is_success)
		return false;

	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_2_GUID);
	is_success = partitioned_block_store_add_partition(
		subject,
		&guid,
		REF_PARTITION_2_STARTING_LBA,
		REF_PARTITION_2_ENDING_LBA,
		0, NULL);

	if (!is_success)
		return false;

	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_3_GUID);
	is_success = partitioned_block_store_add_partition(
		subject,
		&guid,
		REF_PARTITION_3_STARTING_LBA,
		REF_PARTITION_3_ENDING_LBA,
		0, NULL);

	if (!is_success)
		return false;

	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_4_GUID);
	is_success = partitioned_block_store_add_partition(
		subject,
		&guid,
		REF_PARTITION_4_STARTING_LBA,
		REF_PARTITION_4_ENDING_LBA,
		0, NULL);

	return is_success;
}
