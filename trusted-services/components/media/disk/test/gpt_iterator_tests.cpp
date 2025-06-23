/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <cstring>
#include <string>

#include "common/uuid/uuid.h"
#include "media/disk/gpt_iterator/gpt_iterator.h"
#include "media/disk/guid.h"
#include "media/volume/block_volume/block_volume.h"
#include "media/volume/index/volume_index.h"
#include "service/block_storage/config/ref/ref_partition_configurator.h"
#include "service/block_storage/factory/ref_ram_gpt/block_store_factory.h"

TEST_GROUP(GptIteratorTests)
{
	void setup()
	{
		volume_index_init();

		/* Create GPT configured block_store using ref partition configuration */
		m_block_store = ref_ram_gpt_block_store_factory_create();
		CHECK_TRUE(m_block_store);

		/* Use partition exposed for accessing the disk header */
		uuid_guid_octets_from_canonical(&m_partition_guid,
						DISK_GUID_UNIQUE_PARTITION_DISK_HEADER);

		m_volume = NULL;

		int status = block_volume_init(&m_block_volume, m_block_store, &m_partition_guid,
					       &m_volume);

		LONGS_EQUAL(0, status);
		CHECK_TRUE(m_volume);

		status = gpt_iterator_init(&m_iter, m_volume);
		LONGS_EQUAL(0, status);
	}

	void teardown()
	{
		gpt_iterator_deinit(&m_iter);
		block_volume_deinit(&m_block_volume);
		ref_ram_gpt_block_store_factory_destroy(m_block_store);
		volume_index_clear();
	}

	bool check_in_use(const gpt_entry_t *entry)
	{
		struct uuid_octets nil_uuid;

		memset(&nil_uuid, 0, sizeof(nil_uuid));
		return (memcmp(nil_uuid.octets, &entry->type_uuid, sizeof(nil_uuid.octets)) != 0);
	}

	static const uint32_t CLIENT_ID = 0;
	static const size_t FIRST_USABLE_LBA = 34;

	struct uuid_octets m_partition_guid;
	struct block_store *m_block_store;
	struct block_volume m_block_volume;
	struct volume *m_volume;
	struct gpt_iterator m_iter;
};

TEST(GptIteratorTests, iterateOverRefGpt)
{
	/* Expect the reference partition configuration to contain 4 partitions */
	struct uuid_octets guid;
	gpt_entry_t gpt_entry;
	int status;

	/* Set iterator to first entry */
	gpt_iterator_first(&m_iter);
	CHECK_FALSE(gpt_iterator_is_done(&m_iter));

	/* Expect to read ref partition 1 */
	status = gpt_iterator_current(&m_iter, &gpt_entry);
	LONGS_EQUAL(0, status);
	CHECK_TRUE(check_in_use(&gpt_entry));
	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_1_GUID);
	MEMCMP_EQUAL(guid.octets, (uint8_t *)&gpt_entry.unique_uuid, sizeof(guid.octets));
	UNSIGNED_LONGS_EQUAL(FIRST_USABLE_LBA + REF_PARTITION_1_STARTING_LBA, gpt_entry.first_lba);
	UNSIGNED_LONGS_EQUAL((FIRST_USABLE_LBA + REF_PARTITION_1_ENDING_LBA), gpt_entry.last_lba);

	/* Iterate to next */
	gpt_iterator_next(&m_iter);
	CHECK_FALSE(gpt_iterator_is_done(&m_iter));

	/* Expect to read ref partition 2 */
	status = gpt_iterator_current(&m_iter, &gpt_entry);
	LONGS_EQUAL(0, status);
	CHECK_TRUE(check_in_use(&gpt_entry));
	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_2_GUID);
	MEMCMP_EQUAL(guid.octets, (uint8_t *)&gpt_entry.unique_uuid, sizeof(guid.octets));
	UNSIGNED_LONGS_EQUAL(FIRST_USABLE_LBA + REF_PARTITION_2_STARTING_LBA, gpt_entry.first_lba);
	UNSIGNED_LONGS_EQUAL((FIRST_USABLE_LBA + REF_PARTITION_2_ENDING_LBA), gpt_entry.last_lba);

	/* Iterate to next */
	gpt_iterator_next(&m_iter);
	CHECK_FALSE(gpt_iterator_is_done(&m_iter));

	/* Expect to read ref partition 3 */
	status = gpt_iterator_current(&m_iter, &gpt_entry);
	LONGS_EQUAL(0, status);
	CHECK_TRUE(check_in_use(&gpt_entry));
	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_3_GUID);
	MEMCMP_EQUAL(guid.octets, (uint8_t *)&gpt_entry.unique_uuid, sizeof(guid.octets));
	UNSIGNED_LONGS_EQUAL(FIRST_USABLE_LBA + REF_PARTITION_3_STARTING_LBA, gpt_entry.first_lba);
	UNSIGNED_LONGS_EQUAL((FIRST_USABLE_LBA + REF_PARTITION_3_ENDING_LBA), gpt_entry.last_lba);

	/* Iterate to next */
	gpt_iterator_next(&m_iter);
	CHECK_FALSE(gpt_iterator_is_done(&m_iter));

	/* Expect to read ref partition 4 */
	status = gpt_iterator_current(&m_iter, &gpt_entry);
	LONGS_EQUAL(0, status);
	CHECK_TRUE(check_in_use(&gpt_entry));
	uuid_guid_octets_from_canonical(&guid, REF_PARTITION_4_GUID);
	MEMCMP_EQUAL(guid.octets, (uint8_t *)&gpt_entry.unique_uuid, sizeof(guid.octets));
	UNSIGNED_LONGS_EQUAL(FIRST_USABLE_LBA + REF_PARTITION_4_STARTING_LBA, gpt_entry.first_lba);
	UNSIGNED_LONGS_EQUAL((FIRST_USABLE_LBA + REF_PARTITION_4_ENDING_LBA), gpt_entry.last_lba);

	/* Don't expect any other entries to be in-use */
	gpt_iterator_next(&m_iter);

	while (!gpt_iterator_is_done(&m_iter)) {
		status = gpt_iterator_current(&m_iter, &gpt_entry);
		LONGS_EQUAL(0, status);
		CHECK_FALSE(check_in_use(&gpt_entry));

		gpt_iterator_next(&m_iter);
	}
}
