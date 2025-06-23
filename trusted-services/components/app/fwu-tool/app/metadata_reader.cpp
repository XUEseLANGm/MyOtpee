/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "metadata_reader.h"

#include "media/volume/index/volume_index.h"
#include "media/volume/volume.h"
#include "service/fwu/fw_store/banked/volume_id.h"

extern "C" {
#include "trace.h"
}

metadata_reader::metadata_reader()
	: registered_readers()
{
}

metadata_reader::~metadata_reader()
{
}

metadata_reader *metadata_reader::instance()
{
	static metadata_reader the_instance;
	return &the_instance;
}

void metadata_reader::register_reader(metadata_version_specific_reader *reader)
{
	registered_readers.push_back(reader);
}

int metadata_reader::get_boot_info(unsigned int &active_index, unsigned int &metadata_version) const
{
	struct volume *volume;

	int status = volume_index_find(BANKED_VOLUME_ID_PRIMARY_METADATA, &volume);

	if (status) {
		IMSG("Failed to find metadata volume");
		return status;
	}

	status = volume_open(volume);

	if (!status) {
		/* Assume whatever metadata version is in-use, it will fit in the buffer */
		size_t len_read = 0;
		uint8_t buf[1000];

		status = volume_read(volume, (uintptr_t)buf, sizeof(buf), &len_read);

		if (!status) {
			bool is_handled = false;

			for (unsigned int i = 0; i < registered_readers.size(); i++) {
				metadata_version_specific_reader *reader = registered_readers[i];

				if (reader->is_supported(buf, len_read)) {
					reader->get_version(buf, len_read, metadata_version);
					reader->get_active_index(buf, len_read, active_index);

					is_handled = true;
					break;
				}
			}

			if (!is_handled) {
				/* This is normal on first-boot */
				status = -1;
			}

		} else
			IMSG("Failed to read metadata volume");

		volume_close(volume);

	} else
		IMSG("Failed to open metadata volume");

	return status;
}
