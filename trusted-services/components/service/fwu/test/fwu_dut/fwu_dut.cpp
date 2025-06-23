/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fwu_dut.h"

#include <CppUTest/TestHarness.h>
#include <cassert>
#include <cstring>
#include <string>

#include "common/endian/le.h"
#include "service/fwu/test/metadata_checker/metadata_checker_v1.h"
#include "service/fwu/test/metadata_checker/metadata_checker_v2.h"

const char *fwu_dut::VALID_IMAGE_HEADER = "Valid-fw-image-";

fwu_dut::fwu_dut()
	: m_generated_image_count(0)
	, m_metadata_version(1)
{
}

fwu_dut::fwu_dut(unsigned int metadata_version)
	: m_generated_image_count(0)
	, m_metadata_version(metadata_version)
{
}

fwu_dut::~fwu_dut()
{
}

void fwu_dut::generate_image_data(std::vector<uint8_t> *image_data, size_t image_size)
{
	std::string fixed_header(VALID_IMAGE_HEADER);

	/* Image header consists of:
	 *    - Fixed header
	 *    - Image size (32-bit)
	 *    - Sequence count (32-bit)
	 */
	size_t header_len = fixed_header.size() + sizeof(uint32_t) + sizeof(uint32_t);

	/* Reserve space */
	image_data->resize(image_size);

	if (image_size >= header_len) {
		/* Prepare image header */
		memcpy(image_data->data(), fixed_header.data(), fixed_header.size());

		store_u32_le(image_data->data(), fixed_header.size(),
			     static_cast<uint32_t>(image_size));

		store_u32_le(image_data->data(), fixed_header.size() + sizeof(uint32_t),
			     static_cast<uint32_t>(m_generated_image_count));

		/* Fill any remaining space */
		if (image_size > header_len) {
			uint8_t fill_val = static_cast<uint8_t>(m_generated_image_count);
			size_t fill_len = image_size - header_len;

			memset(image_data->data() + header_len, fill_val, fill_len);
		}
	} else if (image_size > 0) {
		/* No room for header so just initialise to fixed value. This will
		 * fail any image verification check.
		 */
		memset(image_data->data(), 0, image_size);
	}

	++m_generated_image_count;
}

void fwu_dut::whole_volume_image_type_uuid(unsigned int location_index,
					   struct uuid_octets *uuid) const
{
	static const char *img_type_guid[] = { "cb0faf2f-f498-49fb-9810-cb09dac1184f",
					       "e9755079-db61-4d90-8a8a-45727eaa1c6e",
					       "d439bc29-83e6-40c7-babe-eb59e415c05e",
					       "433a6c93-8bb0-4966-b49c-dc0c56080d19" };

	CHECK_TRUE(location_index < sizeof(img_type_guid) / sizeof(char *));

	uuid_guid_octets_from_canonical(uuid, img_type_guid[location_index]);
}

metadata_checker *fwu_dut::create_metadata_checker(metadata_fetcher *metadata_fetcher,
						   unsigned int num_images) const
{
	if (m_metadata_version == 1)
		return new metadata_checker_v1(metadata_fetcher, num_images);

	if (m_metadata_version == 2)
		return new metadata_checker_v2(metadata_fetcher, num_images);

	/* Unsupported metadata version */
	assert(false);

	return NULL;
}

unsigned int fwu_dut::metadata_version(void) const
{
	return m_metadata_version;
}
