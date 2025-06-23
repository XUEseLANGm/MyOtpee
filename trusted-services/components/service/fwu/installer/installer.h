/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FWU_INSTALLATION_INSTALLER_H
#define FWU_INSTALLATION_INSTALLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/uuid/uuid.h"
#include "service/fwu/agent/install_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct image_info;
struct fw_directory;

/**
 * \brief Image installer interface
 *
 * The installer_interface structure provides a common interface for
 * any image installer. Concrete installers will implement installation
 * strategies that match the class of image being installed (e.g. component,
 * whole firmware).
 */
struct installer_interface {
	/**
	 * \brief Begin a transaction of one or more image install operations
	 *
	 * \param[in]  context            The concrete installer context
	 * \param[in]  current_volume_id  Where the active fw was loaded from
	 * \param[out] update_volume_id   Where the update should be installed
	 *
	 * \return FWU status
	 */
	int (*begin)(void *context, uint32_t current_volume_id, uint32_t update_volume_id);

	/**
	 * \brief Finalize a transaction of one or more image install operations
	 *
	 * \param[in]  context         The concrete installer context
	 *
	 * \return FWU status
	 */
	int (*finalize)(void *context);

	/**
	 * \brief Abort a transaction
	 *
	 * \param[in]  context         The concrete installer context
	 */
	void (*abort)(void *context);

	/**
	 * \brief Open a stream for writing installation data
	 *
	 * \param[in]  context         The concrete installer context
	 * \param[in]  image_info      Describes the image to install
	 *
	 * \return FWU status
	 */
	int (*open)(void *context, const struct image_info *image_info);

	/**
	 * \brief Commit installed data (called once per open)
	 *
	 * \param[in]  context         The concrete installer context
	 *
	 * \return FWU status
	 */
	int (*commit)(void *context);

	/**
	 * \brief Write installation data to an opened installer
	 *
	 * \param[in]  context         The concrete installer context
	 * \param[in]  data            Data to write
	 * \param[in]  data_len        Length of data
	 *
	 * \return FWU status
	 */
	int (*write)(void *context, const uint8_t *data, size_t data_len);

	/**
	 * \brief Enumerate the collection of images that can be handled by the installer
	 *
	 * A concrete installer will use its specialized knowledge of the associated
	 * storage volume to enumerate the set of images that can be handled by the
	 * installer.
	 *
	 * \param[in]  context         The concrete installer context
	 * \param[in]  volume_id       Identifies the target volume
	 * \param[in]  fw_directory    Add results to this fw_directory
	 *
	 * \return FWU status
	 */
	int (*enumerate)(void *context, uint32_t volume_id, struct fw_directory *fw_directory);
};

/**
 * \brief Base installer structure
 *
 */
struct installer {
	/* The installation type handled by the installer */
	enum install_type install_type;

	/* The location id is a short ID that identifies an updatable logical
	 * portion of the firmware store. The location id only needs to be
	 * unique within the device and will have been assigned dynamically
	 * during FWU configuration. The location id is used to bind a set of
	 * installers to the intended set of target volumes.
	 */
	uint32_t location_id;

	/* The location UUID is a globally unique ID that reflects the same
	 * logical scope as a location id. It is used to associate incoming
	 * update images, either directly or indirectly, to the corresponding
	 * location within the firmware store. For images contained within a
	 * disk partition, this will correspond to the partition type UUID.
	 */
	struct uuid_octets location_uuid;

	/* The opaque context for the concrete installer */
	void *context;

	/* Pointer to a concrete installer_interface */
	const struct installer_interface *interface;

	/* Error status encountered during an update transaction. During an update,
	 * an installer will be called multiple times. If one or more errors are encountered
	 * during the update transaction, the first error status is saved to allow for
	 * appropriate handling.
	 */
	uint32_t install_status;

	/**
	 * During a multi-image update, images may be delegated to different concrete
	 * installers to allow for alternative installation strategies and install destinations.
	 * Each active installer must be sequenced through a begin->finalize transaction to
	 * ensure that installation operations are completed for all images handled by an
	 * installer and by all installers used during the update.
	 */
	bool is_active;
	struct installer *next;
};

static inline bool installer_is_active(const struct installer *installer)
{
	return installer->is_active;
}

static inline uint32_t installer_status(const struct installer *installer)
{
	return installer->install_status;
}

void installer_init(struct installer *installer, enum install_type install_type,
		    uint32_t location_id, const struct uuid_octets *location_uuid, void *context,
		    const struct installer_interface *interface);

int installer_begin(struct installer *installer, uint32_t current_volume_id,
		    uint32_t update_volume_id);

int installer_finalize(struct installer *installer);

void installer_abort(struct installer *installer);

int installer_open(struct installer *installer, const struct image_info *image_info);

int installer_commit(struct installer *installer);

int installer_write(struct installer *installer, const uint8_t *data, size_t data_len);

int installer_enumerate(struct installer *installer, uint32_t volume_id,
			struct fw_directory *fw_directory);

#ifdef __cplusplus
}
#endif

#endif /* FWU_INSTALLATION_INSTALLER_H */
