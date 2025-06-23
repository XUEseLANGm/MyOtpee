/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "volume_metadata_fetcher.h"

#include <CppUTest/TestHarness.h>
#include <cstring>

#include "media/volume/volume.h"

volume_metadata_fetcher::volume_metadata_fetcher(const struct uuid_octets *partition_guid,
						 struct block_store *block_store)
	: metadata_fetcher()
	, m_meta_block_volume()
	, m_meta_volume(NULL)
{
	int status = block_volume_init(&m_meta_block_volume, block_store, partition_guid,
				       &m_meta_volume);
	LONGS_EQUAL(0, status);
	CHECK_TRUE(m_meta_volume);
}

volume_metadata_fetcher::~volume_metadata_fetcher()
{
	block_volume_deinit(&m_meta_block_volume);
}

void volume_metadata_fetcher::open(void)
{
	int status = volume_open(m_meta_volume);
	LONGS_EQUAL(0, status);
}

void volume_metadata_fetcher::close(void)
{
	volume_close(m_meta_volume);
}

void volume_metadata_fetcher::fetch(uint8_t *buf, size_t buf_size)
{
	/* Trash the old data */
	memset(buf, 0xff, buf_size);

	int status = volume_seek(m_meta_volume, IO_SEEK_SET, 0);
	LONGS_EQUAL(0, status);

	size_t length_read = 0;

	status = volume_read(m_meta_volume, (uintptr_t)buf, buf_size, &length_read);

	LONGS_EQUAL(0, status);
	UNSIGNED_LONGS_EQUAL(buf_size, length_read);
}
