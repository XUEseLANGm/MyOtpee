/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FWU_COPY_INSTALLER_H
#define FWU_COPY_INSTALLER_H

#include <stdint.h>

#include "media/volume/volume.h"
#include "service/fwu/installer/installer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief copy_installer structure definition
 *
 * A copy_installer is an installer that copies previously installed images
 * from a source volume into a destination volume. A copy_installer does not
 * consume externally provided installation data. A copy_installer may be
 * used in situations where an update has resulted in no change to the
 * firmware for a subsystem (location) but it is necessary to copy image
 * data to the update bank. The copy_installer has no knowledge of the
 * actual size of image data that needs to copied so the entire source
 * volume is copied to the destination. This will potentially be wasteful
 * in that unnecessary data may be copied.
 */
struct copy_installer {
	struct installer base_installer;
	struct volume *destination_volume;
	struct volume *source_volume;
};

/**
 * \brief Initialize a copy_installer
 *
 * \param[in]  subject    The subject copy_installer
 * \param[in]  location_uuid The associated location UUID
 * \param[in]  location_id Identifies where to install qualifying images
 */
void copy_installer_init(struct copy_installer *subject, const struct uuid_octets *location_uuid,
			 uint32_t location_id);

/**
 * \brief De-initialize a copy_installer
 *
 * \param[in]  subject    The subject copy_installer
 */
void copy_installer_deinit(struct copy_installer *subject);

#ifdef __cplusplus
}
#endif

#endif /* FWU_COPY_INSTALLER_H */
