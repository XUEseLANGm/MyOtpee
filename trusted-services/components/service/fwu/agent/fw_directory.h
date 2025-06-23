/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FW_DIRECTORY_H
#define FW_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/uuid/uuid.h"
#include "install_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The default maximum number of images that can be held by the fw_directory.
 * Can be overridden by an external definition.
 */
#ifndef FWU_MAX_FW_DIRECTORY_ENTRIES
#define FWU_MAX_FW_DIRECTORY_ENTRIES (20)
#endif

/**
 * \brief Boot information structure definition
 *
 * The boot_info structure holds information obtained from the boot loader
 * about the most recent boot.
 */
struct boot_info {
	/* Identifies the bank that was used during boot */
	uint32_t boot_index;

	/* The state of the active_index metadata variable during boot */
	uint32_t active_index;

	/* The state of the previous_active_index metadata variable during boot */
	uint32_t previous_active_index;
};

/**
 * \brief Image information structure definition
 *
 * Information about an updatable image. Firmware may consist of an arbitrary
 * number of images that may be updated as a single unit. Images may correspond
 * to individual components, such as the Crypto SP image, or a collection of
 * components contained within a package understood by firmware such as a FIP.
 */
struct image_info {
	/* Unique identifier for the image type. This corresponds to the UUID/GUID
	 * assigned by the originator of the update package to identify the image.
	 */
	struct uuid_octets img_type_uuid;

	/* The maximum size that can be accommodated for an image of this type.
	 * A platform integrator will have sized back-end storage to provide
	 * sufficient headroom to accommodate updates.
	 */
	size_t max_size;

	/* The lowest accepted version number for this image. This will correspond
	 * to the NV anti-rollback counter value associated with the image.
	 */
	uint32_t lowest_accepted_version;

	/* The version of the currently active version of this image. */
	uint32_t active_version;

	/* Bitmap of access permissions for this image. */
	uint32_t permissions;

	/* The index [0..n] of the image in the fw directory. */
	uint32_t image_index;

	/* The location_id assigned by the platform integrator. A fw_store may
	 * be distributed over multiple locations (e.g. different storage partitions).
	 * The location_id is used to associate installers to storage volumes.
	 */
	uint32_t location_id;

	/* Identifies the type of installation needed for the image. */
	enum install_type install_type;
};

/**
 * \brief Firmware directory structure definition
 *
 * The fw_directory holds information about currently active firmware. Information
 * will have been collected via a trusted pathway. A subset of the information held
 * is presented to external clients.
 */
struct fw_directory {
	struct boot_info boot_info;
	size_t num_images;
	struct image_info entries[FWU_MAX_FW_DIRECTORY_ENTRIES];
};

/**
 * \brief Initialise a fw_directory
 *
 * Initialises the subject fw_directory. After initialisation, the empty fw_directory
 * will need to be populated by a trusted agent (the fw_inspector).
 *
 * \param[in]  fw_directory    The subject fw_directory
 */
void fw_directory_init(struct fw_directory *fw_directory);

/**
 * \brief De-initialise a fw_directory
 *
 * \param[in]  fw_directory    The subject fw_directory
 */
void fw_directory_deinit(struct fw_directory *fw_directory);

/**
 * \brief Sets the boot_info held by the fw_directory
 *
 * Used by a fw_inspector to set the boot_info for the most recent system boot.
 *
 * \param[in]  fw_directory    The subject fw_directory
 * \param[in]  boot_info       boot_info for most recent system boot
 */
void fw_directory_set_boot_info(struct fw_directory *fw_directory,
				const struct boot_info *boot_info);

/**
 * \brief Adds an image_info to the directory
 *
 * Used by a fw_inspector to add an image_info entry to the directory.
 *
 * \param[in]  fw_directory    The subject fw_directory
 * \param[in]  image_info      The entry to add
 *
 * \return FWU status
 */
int fw_directory_add_image_info(struct fw_directory *fw_directory,
				const struct image_info *image_info);

/**
 * \brief Find an image_info entry
 *
 * Query to find an image_info entry using the image type UUID as the key.
 *
 * \param[in]  fw_directory    The subject fw_directory
 * \param[in]  image_type_uuid Image type UUID
 *
 * \return Pointer to image_info or NULL
 */
const struct image_info *fw_directory_find_image_info(const struct fw_directory *fw_directory,
						      const struct uuid_octets *img_type_uuid);

/**
 * \brief Get the boot_info
 *
 * \param[in]  fw_directory    The subject fw_directory
 *
 * \return Pointer to the boot_info
 */
const struct boot_info *fw_directory_get_boot_info(const struct fw_directory *fw_directory);

/**
 * \brief Get an image_info by index
 *
 * Can be used for iterating over all image_info objects held.
 *
 * \param[in]  fw_directory    The subject fw_directory
 * \param[in]  index           Index in range [0..num_images-1]
 *
 * \return Pointer to the image_info or NULL if index invalid
 */
const struct image_info *fw_directory_get_image_info(const struct fw_directory *fw_directory,
						     size_t index);

/**
 * \brief Get the number of image_info entries held
 *
 * \param[in]  fw_directory    The subject fw_directory
 *
 * \return Number of entries
 */
size_t fw_directory_num_images(const struct fw_directory *fw_directory);

#ifdef __cplusplus
}
#endif

#endif /* FW_DIRECTORY_H */
