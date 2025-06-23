/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "fwu_configure.h"

#include <service/fwu/config/gpt/gpt_fwu_configure.h>

#include "media/volume/factory/volume_factory.h"
#include "media/volume/index/volume_index.h"
#include "service/fwu/installer/factory/installer_factory.h"
#include "service/fwu/installer/installer_index.h"

int fwu_configure(const struct uuid_octets *device_uuids, size_t num_device_uuids)
{
	unsigned int location_id = 0;

	volume_index_init();
	installer_index_init();

	for (size_t i = 0; i < num_device_uuids; i++) {
		unsigned int new_location_count = 0;

		int status = gpt_fwu_configure(&device_uuids[i], location_id, &new_location_count);

		if (status)
			return status;

		location_id += new_location_count;
	}

	return 0;
}

void fwu_deconfigure(void)
{
	unsigned int index = 0;

	/* Destroy installers */
	while (1) {
		struct installer *installer = installer_index_get(index);

		if (installer)
			installer_factory_destroy_installer(installer);
		else
			break;

		++index;
	}

	/* Destroy volumes */
	index = 0;

	while (1) {
		struct volume *volume = volume_index_get(index);

		if (volume)
			volume_factory_destroy_volume(volume);
		else
			break;

		++index;
	}

	installer_index_clear();
	volume_index_clear();
}
