/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <cstring>
#include <string>

#include "common/uuid/uuid.h"
#include "media/volume/block_volume/block_volume.h"
#include "media/volume/index/volume_index.h"
#include "service/block_storage/block_store/device/ram/ram_block_store.h"

TEST_GROUP(BlockVolumeTests)
{
	void setup()
	{
		uuid_guid_octets_from_canonical(&m_partition_guid,
						"6152f22b-8128-4c1f-981f-3bd279519907");

		m_block_store = ram_block_store_init(&m_ram_block_store, &m_partition_guid,
						     NUM_BLOCKS, BLOCK_SIZE);

		CHECK_TRUE(m_block_store);

		m_volume = NULL;

		int result = block_volume_init(&m_block_volume, m_block_store, &m_partition_guid,
					       &m_volume);

		LONGS_EQUAL(0, result);
		CHECK_TRUE(m_volume);

		volume_index_init();
		volume_index_add(TEST_VOLUME_ID, m_volume);
	}

	void teardown()
	{
		block_volume_deinit(&m_block_volume);
		ram_block_store_deinit(&m_ram_block_store);
		volume_index_clear();
	}

	static const unsigned int TEST_VOLUME_ID = 5;
	static const size_t NUM_BLOCKS = 100;
	static const size_t BLOCK_SIZE = 512;

	struct uuid_octets m_partition_guid;
	struct block_store *m_block_store;
	struct ram_block_store m_ram_block_store;
	struct block_volume m_block_volume;
	struct volume *m_volume;
};

TEST(BlockVolumeTests, openClose)
{
	/* Check the open flow used by tf-a components */
	uintptr_t dev_handle = 0;
	uintptr_t io_spec = 0;
	uintptr_t file_handle = 0;
	int result;

	result = plat_get_image_source(TEST_VOLUME_ID, &dev_handle, &io_spec);
	LONGS_EQUAL(0, result);
	CHECK_TRUE(dev_handle);

	result = io_open(dev_handle, io_spec, &file_handle);
	LONGS_EQUAL(0, result);
	CHECK_TRUE(file_handle);

	io_close(file_handle);
}

TEST(BlockVolumeTests, readAndWrite)
{
	int result = volume_open(m_volume);
	LONGS_EQUAL(0, result);

	std::string message("Oh what a beautiful mornin'");

	/* Ensure writes cross a block boundary */
	size_t num_iterations = BLOCK_SIZE / message.size() + 2;

	/* Write message a few times. Expect file pointer to advance on each write */
	for (size_t i = 0; i < num_iterations; ++i) {
		size_t len_written = 0;

		result = volume_write(m_volume, (const uintptr_t)message.c_str(), message.size(),
				      &len_written);

		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(message.size(), len_written);
	}

	result = volume_seek(m_volume, IO_SEEK_SET, 0);
	LONGS_EQUAL(0, result);

	/* Expect to read back the same data */
	uint8_t read_buf[message.size()];

	for (size_t i = 0; i < num_iterations; ++i) {
		size_t len_read = 0;

		memset(read_buf, 0, sizeof(read_buf));

		result = volume_read(m_volume, (const uintptr_t)read_buf, sizeof(read_buf),
				     &len_read);

		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(message.size(), len_read);
		MEMCMP_EQUAL(message.c_str(), read_buf, message.size());
	}

	result = volume_close(m_volume);
	LONGS_EQUAL(0, result);
}

TEST(BlockVolumeTests, seekAccess)
{
	size_t len = 0;

	int result = volume_open(m_volume);
	LONGS_EQUAL(0, result);

	std::string message("Knees up Mother Brown");

	/* Initially seek to an arbitrary position around the middle of the volume */
	size_t start_pos = (NUM_BLOCKS * BLOCK_SIZE) / 2 + 27;

	/* Seek and write a few times */
	result = volume_seek(m_volume, IO_SEEK_SET, start_pos);
	LONGS_EQUAL(0, result);

	result = volume_write(m_volume, (const uintptr_t)message.c_str(), message.size(), &len);
	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(message.size(), len);

	/* Using IO_SEEK_SET, seek forward, skipping over the written message */
	result = volume_seek(m_volume, IO_SEEK_SET, start_pos + 110);
	LONGS_EQUAL(0, result);

	result = volume_write(m_volume, (const uintptr_t)message.c_str(), message.size(), &len);
	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(message.size(), len);

	/* Using IO_SEEK_CUR, seek forward again, far enough to skip over the message */
	result = volume_seek(m_volume, IO_SEEK_CUR, 715);
	LONGS_EQUAL(0, result);

	result = volume_write(m_volume, (const uintptr_t)message.c_str(), message.size(), &len);
	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(message.size(), len);

	/* Perform the same sequence of seeks and expect to read back intact copies of the message */
	uint8_t read_buf[message.size()];

	result = volume_seek(m_volume, IO_SEEK_SET, start_pos);
	LONGS_EQUAL(0, result);

	result = volume_read(m_volume, (uintptr_t)read_buf, sizeof(read_buf), &len);
	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(message.size(), len);
	MEMCMP_EQUAL(message.c_str(), read_buf, message.size());

	result = volume_seek(m_volume, IO_SEEK_SET, start_pos + 110);
	LONGS_EQUAL(0, result);

	result = volume_read(m_volume, (uintptr_t)read_buf, sizeof(read_buf), &len);
	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(message.size(), len);
	MEMCMP_EQUAL(message.c_str(), read_buf, message.size());

	result = volume_seek(m_volume, IO_SEEK_CUR, 715);
	LONGS_EQUAL(0, result);

	result = volume_read(m_volume, (uintptr_t)read_buf, sizeof(read_buf), &len);
	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(message.size(), len);
	MEMCMP_EQUAL(message.c_str(), read_buf, message.size());

	result = volume_close(m_volume);
	LONGS_EQUAL(0, result);
}

TEST(BlockVolumeTests, multipleImageInstall)
{
	/* Test that a sequence of image install operations can be applied
	 * to the same volume. Prior to performing streamed write operations to
	 * install an image, the previous content must be erased, if the backend
	 * storage requires this e.g. for NOR flash. */

	struct volume *volume = NULL;
	int result;

	result = volume_index_find(TEST_VOLUME_ID, &volume);
	LONGS_EQUAL(0, result);
	CHECK_TRUE(volume);

	for (size_t i = 0; i < 3; ++i) {
		size_t len = 0;

		/* Each iteration represents an update installation where arbitrary sized
		 * chunks are written to the storage volume. */
		result = volume_open(volume);
		LONGS_EQUAL(0, result);

		/* Writes will only succeed if the written blocks have already been erased.
		 * By repeatedly writing to the same blocks, this test verifies that the erase
		 * must be working correctly.
		 */
		result = volume_erase(volume);
		LONGS_EQUAL(0, result);

		std::string chunk1("The first chunk of the update image");
		result = volume_write(volume, (const uintptr_t)chunk1.c_str(), chunk1.size(), &len);
		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(chunk1.size(), len);

		std::string chunk2("And the second");
		result = volume_write(volume, (const uintptr_t)chunk2.c_str(), chunk2.size(), &len);
		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(chunk2.size(), len);

		std::string chunk3("The third chunk is soooooooooooooooooooooooooooo much longer");
		result = volume_write(volume, (const uintptr_t)chunk3.c_str(), chunk3.size(), &len);
		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(chunk3.size(), len);

		/* Try reading it all back */
		std::string expected_data = chunk1 + chunk2 + chunk3;
		uint8_t read_buf[expected_data.size()];

		result = volume_seek(volume, IO_SEEK_SET, 0);
		LONGS_EQUAL(0, result);

		result = volume_read(volume, (uintptr_t)read_buf, sizeof(read_buf), &len);
		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(expected_data.size(), len);
		MEMCMP_EQUAL(expected_data.c_str(), read_buf, expected_data.size());

		result = volume_close(volume);
		LONGS_EQUAL(0, result);
	}
}

TEST(BlockVolumeTests, oversizeWrite)
{
	int result = volume_open(m_volume);
	LONGS_EQUAL(0, result);

	size_t vol_size;
	result = volume_size(m_volume, &vol_size);
	LONGS_EQUAL(0, result);
	CHECK_TRUE(vol_size > 0);

	std::string message("Message to be written many many times");

	/* Expect to be able write the whole message lots of times without error */
	size_t num_whole_messages = vol_size / message.size();
	size_t space_remaining = vol_size % message.size();

	/* Expect there to be remaining bytes free at the end of the volume*/
	CHECK_TRUE(space_remaining > 0);

	for (size_t i = 0; i < num_whole_messages; ++i) {
		size_t len_written = 0;

		result = volume_write(m_volume, (const uintptr_t)message.c_str(), message.size(),
				      &len_written);

		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(message.size(), len_written);
	}

	/* Writing the message one more time should exceed the volume size */
	size_t len_written = 0;

	result = volume_write(m_volume, (const uintptr_t)message.c_str(), message.size(),
			      &len_written);

	LONGS_EQUAL(0, result);

	/* Expect the number of bytes written gets truncated to the size limit of the volume */
	UNSIGNED_LONGS_EQUAL(space_remaining, len_written);

	result = volume_seek(m_volume, IO_SEEK_SET, 0);
	LONGS_EQUAL(0, result);

	/* Expect to read back the same number of whole messages */
	uint8_t read_buf[message.size()];

	for (size_t i = 0; i < num_whole_messages; ++i) {
		size_t len_read = 0;

		memset(read_buf, 0, sizeof(read_buf));

		result = volume_read(m_volume, (const uintptr_t)read_buf, sizeof(read_buf),
				     &len_read);

		LONGS_EQUAL(0, result);
		UNSIGNED_LONGS_EQUAL(message.size(), len_read);
		MEMCMP_EQUAL(message.c_str(), read_buf, message.size());
	}

	/* Expect final read to be truncated to the end of the volume */
	size_t len_read = 0;

	memset(read_buf, 0, sizeof(read_buf));

	result = volume_read(m_volume, (const uintptr_t)read_buf, sizeof(read_buf), &len_read);

	LONGS_EQUAL(0, result);
	UNSIGNED_LONGS_EQUAL(space_remaining, len_read);
	MEMCMP_EQUAL(message.c_str(), read_buf, space_remaining);

	result = volume_close(m_volume);
	LONGS_EQUAL(0, result);
}
