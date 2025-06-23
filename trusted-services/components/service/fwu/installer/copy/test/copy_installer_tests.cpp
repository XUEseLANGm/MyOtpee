/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <cstdlib>
#include <cstring>

#include "common/uuid/uuid.h"
#include "media/disk/guid.h"
#include "media/volume/block_volume/block_volume.h"
#include "media/volume/index/volume_index.h"
#include "media/volume/volume.h"
#include "service/block_storage/config/ref/ref_partition_configurator.h"
#include "service/block_storage/factory/ref_ram_gpt/block_store_factory.h"
#include "service/fwu/agent/fw_directory.h"
#include "service/fwu/fw_store/banked/volume_id.h"
#include "service/fwu/installer/copy/copy_installer.h"
#include "service/fwu/installer/installer_index.h"
#include "service/fwu/installer/raw/raw_installer.h"

TEST_GROUP(FwuCopyInstallerTests)
{
	void setup()
	{
		int result;
		struct uuid_octets partition_guid;

		m_image = NULL;

		installer_index_init();
		volume_index_init();

		/* Use the reference disk configuration and use partition 1 & 2 as
		 * storage for A and B firmware banks.
		 */
		m_block_store = ref_ram_gpt_block_store_factory_create();

		/* Construct fw volume A */
		uuid_guid_octets_from_canonical(&partition_guid, REF_PARTITION_1_GUID);

		result = block_volume_init(&m_block_volume_a, m_block_store, &partition_guid,
					   &m_fw_volume_a);

		LONGS_EQUAL(0, result);
		CHECK_TRUE(m_fw_volume_a);

		/* Construct fw volume B */
		uuid_guid_octets_from_canonical(&partition_guid, REF_PARTITION_2_GUID);

		result = block_volume_init(&m_block_volume_b, m_block_store, &partition_guid,
					   &m_fw_volume_b);

		LONGS_EQUAL(0, result);
		CHECK_TRUE(m_fw_volume_b);

		/* Prepare an image_info structure to describe the image to
		 * install into one of volumes.
		 */
		uuid_guid_octets_from_canonical(&m_image_info.img_type_uuid,
						"1c22ca2c-9732-49e6-ba3b-eed40e27fda3");

		m_image_info.max_size =
			(REF_PARTITION_1_ENDING_LBA - REF_PARTITION_1_STARTING_LBA + 1) *
			REF_PARTITION_BLOCK_SIZE;
		m_image_info.lowest_accepted_version = 1;
		m_image_info.active_version = 1;
		m_image_info.permissions = 0;
		m_image_info.image_index = 0;
		m_image_info.location_id = FW_STORE_LOCATION_ID;
		m_image_info.install_type = INSTALL_TYPE_WHOLE_VOLUME;

		/* Mimic a platform configuration where storage volumes are assigned
		 * location and usage IDs. These usage IDs correspond to an A/B banked
		 * firmware store.
		 */
		volume_index_add(banked_volume_id(FW_STORE_LOCATION_ID, BANKED_USAGE_ID_FW_BANK_A),
				 m_fw_volume_a);
		volume_index_add(banked_volume_id(FW_STORE_LOCATION_ID, BANKED_USAGE_ID_FW_BANK_B),
				 m_fw_volume_b);

		/* A platform configuration will also determine which installers are
		 * assigned to which locations. For these tests, there is a raw_installer
		 * to install the initial image and a copy_installer to install a copy
		 * into the other bank.
		 */
		raw_installer_init(&m_raw_installer, &m_image_info.img_type_uuid,
				   FW_STORE_LOCATION_ID);
		installer_index_register(&m_raw_installer.base_installer);

		copy_installer_init(&m_copy_installer, &m_image_info.img_type_uuid,
				    FW_STORE_LOCATION_ID);
		installer_index_register(&m_copy_installer.base_installer);
	}

	void teardown()
	{
		delete[] m_image;

		raw_installer_deinit(&m_raw_installer);
		copy_installer_deinit(&m_copy_installer);

		installer_index_clear();
		volume_index_clear();

		block_volume_deinit(&m_block_volume_a);
		block_volume_deinit(&m_block_volume_b);
		ref_ram_gpt_block_store_factory_destroy(m_block_store);
	}

	void create_image(size_t len)
	{
		m_image = new uint8_t[len];
		m_image_len = len;

		for (size_t i = 0; i < len; i++)
			m_image[i] = (uint8_t)rand();
	}

	void install_initial_image(size_t len)
	{
		create_image(len);

		/* Expect to find a suitable installer for the given image_info */
		struct installer *installer =
			installer_index_find(m_image_info.install_type, m_image_info.location_id);
		CHECK_TRUE(installer);
		UNSIGNED_LONGS_EQUAL(FW_STORE_LOCATION_ID, installer->location_id);

		/* Begin installation transaction - installing into volume A */
		int status = installer_begin(
			installer,
			banked_volume_id(FW_STORE_LOCATION_ID,
					 BANKED_USAGE_ID_FW_BANK_B), /* Current volume */
			banked_volume_id(FW_STORE_LOCATION_ID,
					 BANKED_USAGE_ID_FW_BANK_A)); /* Update volume */
		LONGS_EQUAL(0, status);

		status = installer_open(installer, &m_image_info);
		LONGS_EQUAL(0, status);

		status = installer_write(installer, m_image, m_image_len);
		LONGS_EQUAL(0, status);

		status = installer_commit(installer);
		LONGS_EQUAL(0, status);

		status = installer_finalize(installer);
		LONGS_EQUAL(0, status);

		check_update_installed(m_fw_volume_a);
	}

	void check_update_installed(struct volume * volume)
	{
		int status = 0;
		size_t total_read = 0;

		status = volume_open(volume);
		LONGS_EQUAL(0, status);

		while (total_read < m_image_len) {
			uint8_t read_buf[1000];
			size_t len_read = 0;
			size_t bytes_remaining = m_image_len - total_read;
			size_t req_len = (bytes_remaining > sizeof(read_buf)) ? sizeof(read_buf) :
										bytes_remaining;

			memset(read_buf, 0, sizeof(read_buf));

			status = volume_read(volume, (uintptr_t)read_buf, req_len, &len_read);
			LONGS_EQUAL(0, status);
			UNSIGNED_LONGS_EQUAL(req_len, len_read);

			MEMCMP_EQUAL(&m_image[total_read], read_buf, len_read);

			total_read += len_read;
		}

		status = volume_close(volume);
		LONGS_EQUAL(0, status);
	}

	static const unsigned int FW_STORE_LOCATION_ID = 0x100;

	struct block_store *m_block_store;
	struct block_volume m_block_volume_a;
	struct block_volume m_block_volume_b;
	struct volume *m_fw_volume_a;
	struct volume *m_fw_volume_b;
	struct raw_installer m_raw_installer;
	struct copy_installer m_copy_installer;
	struct image_info m_image_info;
	uint8_t *m_image;
	size_t m_image_len;
};

TEST(FwuCopyInstallerTests, installAndCopy)
{
	/* Install an arbitrary size image into bank A */
	install_initial_image(13011);

	/* Expect to find a suitable copy installer */
	struct installer *installer =
		installer_index_find(INSTALL_TYPE_WHOLE_VOLUME_COPY, FW_STORE_LOCATION_ID);
	CHECK_TRUE(installer);
	UNSIGNED_LONGS_EQUAL(FW_STORE_LOCATION_ID, installer->location_id);

	/* Begin installation transaction - installing into volume B */
	int status =
		installer_begin(installer,
				banked_volume_id(FW_STORE_LOCATION_ID,
						 BANKED_USAGE_ID_FW_BANK_A), /* Current volume */
				banked_volume_id(FW_STORE_LOCATION_ID,
						 BANKED_USAGE_ID_FW_BANK_B)); /* Update volume */
	LONGS_EQUAL(0, status);

	/* Finalize the installation -  the copy should happen here */
	status = installer_finalize(installer);
	LONGS_EQUAL(0, status);

	/* Expect volume B to contain a copy of what's in volume A */
	check_update_installed(m_fw_volume_b);
}
