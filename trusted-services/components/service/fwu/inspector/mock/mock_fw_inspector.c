/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "mock_fw_inspector.h"

#include "common/uuid/uuid.h"
#include "service/fwu/agent/fw_directory.h"

int mock_fw_inspector_inspect(struct fw_directory *fw_dir, unsigned int boot_index)
{
	(void)boot_index;

	/* A mock fw inspector that populates the fw_directory with fixed entries.
	 * Intended for test purposes.
	 */

	/* Add some mock image entries to represent updatable units. */
	struct image_info image_info = { 0 };

	/* Image 1 */
	uuid_guid_octets_from_canonical(&image_info.img_type_uuid, MOCK_IMG_TYPE_UUID_1);
	image_info.max_size = 100;
	image_info.lowest_accepted_version = 1;
	image_info.active_version = 2;
	image_info.permissions = 1;
	image_info.install_type = INSTALL_TYPE_WHOLE_VOLUME;

	fw_directory_add_image_info(fw_dir, &image_info);

	/* Image 2 */
	uuid_guid_octets_from_canonical(&image_info.img_type_uuid, MOCK_IMG_TYPE_UUID_2);
	image_info.max_size = 100;
	image_info.lowest_accepted_version = 1;
	image_info.active_version = 2;
	image_info.permissions = 1;
	image_info.install_type = INSTALL_TYPE_SUB_VOLUME;

	fw_directory_add_image_info(fw_dir, &image_info);

	/* Image 3 */
	uuid_guid_octets_from_canonical(&image_info.img_type_uuid, MOCK_IMG_TYPE_UUID_3);
	image_info.max_size = 100;
	image_info.lowest_accepted_version = 1;
	image_info.active_version = 2;
	image_info.permissions = 1;
	image_info.install_type = INSTALL_TYPE_SUB_VOLUME;

	fw_directory_add_image_info(fw_dir, &image_info);

	/* Image 4 */
	uuid_guid_octets_from_canonical(&image_info.img_type_uuid, MOCK_IMG_TYPE_UUID_4);
	image_info.max_size = 200;
	image_info.lowest_accepted_version = 1;
	image_info.active_version = 2;
	image_info.permissions = 1;
	image_info.install_type = INSTALL_TYPE_SUB_VOLUME;

	fw_directory_add_image_info(fw_dir, &image_info);

	return 0;
}
