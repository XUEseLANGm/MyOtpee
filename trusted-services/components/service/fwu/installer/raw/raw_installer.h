/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FWU_RAW_INSTALLER_H
#define FWU_RAW_INSTALLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/uuid/uuid.h"
#include "media/volume/volume.h"
#include "service/fwu/installer/installer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief raw_installer structure definition
 *
 * A raw_installer is an installer that takes the raw input image and writes
 * it directly to the target storage volume with no intermediate processing.
 * The raw_installer can be used for say installing a complete firmware image
 * into a single volume. Because the raw_installer has no knowledge of the
 * format of images that it installs, the assigned location_uuid is used
 * by the enumerate method to advertise a single updatable image that
 * corresponds to the entire raw contents of the associated target
 * volume. Other sub-volume installers may advertise additional updatable
 * images that reside within the same target volume.
 */
struct raw_installer {
	struct installer base_installer;
	struct volume *target_volume;
	unsigned int commit_count;
	size_t bytes_written;
	bool is_open;
};

/**
 * \brief Initialize a raw_installer
 *
 * \param[in]  subject    The subject raw_installer
 * \param[in]  location_uuid The associated location UUID
 * \param[in]  location_id Identifies where to install qualifying images
 */
void raw_installer_init(struct raw_installer *subject, const struct uuid_octets *location_uuid,
			uint32_t location_id);

/**
 * \brief De-initialize a raw_installer
 *
 * \param[in]  subject    The subject raw_installer
 */
void raw_installer_deinit(struct raw_installer *subject);

#ifdef __cplusplus
}
#endif

#endif /* FWU_RAW_INSTALLER_H */
