/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stddef.h>
#include <common/uuid/uuid.h>
#include <media/disk/guid.h>
#include <media/disk/partition_table.h>
#include "gpt_partition_configurator.h"

static bool gpt_partition_config_listener(
	struct partitioned_block_store *subject,
	const struct uuid_octets *partition_guid,
	const struct storage_partition_info *back_store_info)
{
	/* Performs on-demand partition configuration on an attempt to
	 * open an unconfigured storage partition.
	 */
	bool is_configured = false;
	const partition_entry_t *partition_entry = NULL;

	/* Check if matching partition entry exists in loaded GPT */
	partition_entry = get_partition_entry_by_uuid((uuid_t *)partition_guid->octets);

	if (partition_entry &&
		back_store_info->block_size &&
		(partition_entry->length >= back_store_info->block_size) &&
		!(partition_entry->length % back_store_info->block_size)) {

		/* Partition entry exists and values look sane */
		uint64_t starting_lba =
			partition_entry->start / back_store_info->block_size;
		uint64_t ending_lba =
			starting_lba + (partition_entry->length / back_store_info->block_size) - 1;

		if (ending_lba >= starting_lba) {

			is_configured = partitioned_block_store_add_partition(
				subject, partition_guid,
				starting_lba, ending_lba,
				0, NULL);
		}
	}

	return is_configured;
}

static bool add_disk_header_partition(
	struct partitioned_block_store *subject)
{
	/* Adds a partition to make the MBR/GPT readable via a separate partition. This
	 * enables clients to retrieve information from the GPT for their own configuration
	 * purposes.
	 */
	const struct storage_partition_info *disk_info =
		partitioned_block_store_get_back_store_info(subject);

	size_t entry_table_size = PLAT_PARTITION_MAX_ENTRIES * sizeof(gpt_entry_t);
	size_t disk_header_size = GPT_ENTRY_OFFSET + entry_table_size;
	size_t num_header_blocks =
		(disk_header_size + disk_info->block_size - 1) / disk_info->block_size;

	if (num_header_blocks > 0 && num_header_blocks <= disk_info->num_blocks) {

		struct uuid_octets partition_guid;

		uuid_guid_octets_from_canonical(&partition_guid,
			DISK_GUID_UNIQUE_PARTITION_DISK_HEADER);

		uint32_t starting_lba = 0;
		uint32_t ending_lba = starting_lba + num_header_blocks - 1;

		return partitioned_block_store_add_partition(
			subject, &partition_guid,
			starting_lba, ending_lba,
			0, NULL);
	}

	return false;
}

bool gpt_partition_configure(
	struct partitioned_block_store *subject,
	unsigned int volume_id)
{
	bool success = false;
	int result = load_partition_table(volume_id);

	if ((result == 0) && add_disk_header_partition(subject)) {

		partitioned_block_store_attach_config_listener(
			subject,
			gpt_partition_config_listener);

		success = true;
	}

	return success;
}
