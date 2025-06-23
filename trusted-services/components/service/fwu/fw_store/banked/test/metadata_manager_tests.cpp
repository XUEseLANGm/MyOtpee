/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <stdlib.h>

#include "common/uuid/uuid.h"
#include "media/disk/guid.h"
#include "media/volume/block_volume/block_volume.h"
#include "media/volume/index/volume_index.h"
#include "media/volume/volume.h"
#include "service/block_storage/factory/ref_ram_gpt/block_store_factory.h"
#include "service/fwu/agent/fw_directory.h"
#include "service/fwu/fw_store/banked/bank_tracker.h"
#include "service/fwu/fw_store/banked/metadata_manager.h"
#include "service/fwu/fw_store/banked/metadata_serializer/metadata_serializer.h"
#include "service/fwu/fw_store/banked/metadata_serializer/v1/metadata_serializer_v1.h"
#include "service/fwu/fw_store/banked/volume_id.h"
#include "service/fwu/inspector/mock/mock_fw_inspector.h"

TEST_GROUP(FwuMetadataManagerTests)
{
	void setup()
	{
		int result;
		struct uuid_octets partition_guid;

		/* Default to V1 metadata serializer */
		m_serializer = metadata_serializer_v1();

		/* Construct storage */
		volume_index_init();
		m_block_store = ref_ram_gpt_block_store_factory_create();

		/* Construct primary metadata volume */
		uuid_guid_octets_from_canonical(&partition_guid,
						DISK_GUID_UNIQUE_PARTITION_PRIMARY_FWU_METADATA);

		result = block_volume_init(&m_primary_block_volume, m_block_store, &partition_guid,
					   &m_primary_volume);

		LONGS_EQUAL(0, result);
		CHECK_TRUE(m_primary_volume);

		/* Construct backup metadata volume */
		uuid_guid_octets_from_canonical(&partition_guid,
						DISK_GUID_UNIQUE_PARTITION_BACKUP_FWU_METADATA);

		result = block_volume_init(&m_backup_block_volume, m_block_store, &partition_guid,
					   &m_backup_volume);

		LONGS_EQUAL(0, result);
		CHECK_TRUE(m_backup_volume);

		bank_tracker_init(&m_bank_tracker);
		fw_directory_init(&m_fw_directory);

		result = mock_fw_inspector_inspect(&m_fw_directory, BOOT_INDEX);
		LONGS_EQUAL(0, result);
	}

	void teardown()
	{
		metadata_manager_deinit(&m_metadata_manager);
		fw_directory_deinit(&m_fw_directory);
		bank_tracker_deinit(&m_bank_tracker);

		volume_index_clear();
		block_volume_deinit(&m_primary_block_volume);
		block_volume_deinit(&m_backup_block_volume);
		ref_ram_gpt_block_store_factory_destroy(m_block_store);
	}

	void corrupt_metadata(struct volume * volume)
	{
		int status;
		size_t metadata_size = m_serializer->size(&m_fw_directory);
		uint8_t metadata_buf[metadata_size];
		size_t actual_len = 0;

		status = volume_open(volume);
		LONGS_EQUAL(0, status);

		status = volume_read(volume, (uintptr_t)metadata_buf, metadata_size, &actual_len);
		LONGS_EQUAL(0, status);
		UNSIGNED_LONGS_EQUAL(metadata_size, actual_len);

		/* Corrupt the first byte */
		metadata_buf[0] ^= 0xff;

		/* Erase contents and write back the corrupted copy */
		status = volume_erase(volume);
		LONGS_EQUAL(0, status);

		status = volume_seek(volume, IO_SEEK_SET, 0);
		LONGS_EQUAL(0, status);

		status = volume_write(volume, (const uintptr_t)metadata_buf, metadata_size,
				      &actual_len);
		LONGS_EQUAL(0, status);
		UNSIGNED_LONGS_EQUAL(metadata_size, actual_len);

		volume_close(volume);
	}

	static const unsigned int BOOT_INDEX = 1;

	struct block_store *m_block_store;
	struct block_volume m_primary_block_volume;
	struct block_volume m_backup_block_volume;
	struct volume *m_primary_volume;
	struct volume *m_backup_volume;
	struct metadata_manager m_metadata_manager;
	struct fw_directory m_fw_directory;
	struct bank_tracker m_bank_tracker;
	const struct metadata_serializer *m_serializer;
};

TEST(FwuMetadataManagerTests, checkAndRepairAccessibleStorage)
{
	int result = 0;

	/* Check configuration where metadata storage is accessible. Because neither
	 * metadata copy has been initialized, initially expect the check and repair
	 * operation to fail. */
	result = volume_index_add(BANKED_VOLUME_ID_PRIMARY_METADATA, m_primary_volume);
	LONGS_EQUAL(0, result);
	result = volume_index_add(BANKED_VOLUME_ID_BACKUP_METADATA, m_backup_volume);
	LONGS_EQUAL(0, result);

	result = metadata_manager_init(&m_metadata_manager, m_serializer);
	LONGS_EQUAL(0, result);

	result = metadata_manager_check_and_repair(&m_metadata_manager, &m_fw_directory);
	CHECK_TRUE(result != 0);

	/* An update to the metadata should result in both primary and backup copies
	 * being initialized. */
	result = metadata_manager_update(&m_metadata_manager, 0, 1, &m_fw_directory,
					 &m_bank_tracker);
	LONGS_EQUAL(0, result);

	/* If the update was successful, check_and_repair shouldn't have anything to do. */
	result = metadata_manager_check_and_repair(&m_metadata_manager, &m_fw_directory);
	LONGS_EQUAL(0, result);

	/* Invalidating the cache should force a reload but expect both volumes to hold
	 * valid data.*/
	metadata_manager_cache_invalidate(&m_metadata_manager);
	result = metadata_manager_check_and_repair(&m_metadata_manager, &m_fw_directory);
	LONGS_EQUAL(0, result);

	/* Corrupt either copy randomly a few times and expect to always repair */
	for (size_t i = 0; i < 100; ++i) {
		struct volume *volume = (rand() & 1) ? m_primary_volume : m_backup_volume;

		corrupt_metadata(volume);
		metadata_manager_cache_invalidate(&m_metadata_manager);
		result = metadata_manager_check_and_repair(&m_metadata_manager, &m_fw_directory);
		LONGS_EQUAL(0, result);
	}

	/* Corrupt both copies - repair should not be possible */
	corrupt_metadata(m_primary_volume);
	corrupt_metadata(m_backup_volume);
	metadata_manager_cache_invalidate(&m_metadata_manager);
	result = metadata_manager_check_and_repair(&m_metadata_manager, &m_fw_directory);
	CHECK_TRUE(result != 0);
}

TEST(FwuMetadataManagerTests, checkAndRepairInaccessibleStorage)
{
	int result = 0;

	/* Check configuration where metadata storage is inaccessible (i.e. no
	 * volumes added to volume_index). Expect the check to fail, indicating
	 * that an update is required to initialise the cache. */
	result = metadata_manager_init(&m_metadata_manager, m_serializer);
	LONGS_EQUAL(0, result);

	result = metadata_manager_check_and_repair(&m_metadata_manager, &m_fw_directory);
	CHECK_TRUE(result != 0);
}