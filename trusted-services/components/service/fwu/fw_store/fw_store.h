/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FW_STORE_H
#define FW_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct fw_store;
struct fw_directory;
struct image_info;
struct installer;
struct uuid_octets;

/**
 * \brief Synchronize fw_store state to the active state of the firmware
 *
 * Synchronizes the state of the fw_store to reflect the state of the
 * booted firmware obtained from the firmware directory. The firmware directory
 * will have been populated with information obtained from trusted
 * sources such as the attestation service.
 *
 * \param[in]  fw_store    The subject fw_store
 * \param[in]  fw_dir      The firmware directory to synchronize to
 * \param[in]  boot_index  The boot_index reported by the bootloader
 *
 * \return FWU status code
 */
int fw_store_synchronize(struct fw_store *fw_store, struct fw_directory *fw_dir,
			 unsigned int boot_index);

/**
 * \brief Begin to install one or more images
 *
 * Should be called prior to installing one or more images into this fw_store.
 * As long as success is returned, installation operations may follow.
 *
 * \param[in]  fw_store  The subject fw_store
 *
 * \return FWU status code
 */
int fw_store_begin_install(struct fw_store *fw_store);

/**
 * \brief Cancel any install operation in progress
 *
 * \param[in]  fw_store  The subject fw_store
 */
void fw_store_cancel_install(struct fw_store *fw_store);

/**
 * \brief Finalize the installation of a set of images
 *
 * Should be called after installing all images. Once finalized, the new
 * installation may be activated in preparation for a trial of the update.
 *
 * \param[in]  fw_store  The subject fw_store
 *
 * \return FWU status code
 */
int fw_store_finalize_install(struct fw_store *fw_store);

/**
 * \brief Select an installer
 *
 * Select an installer to handle installation of the image described by
 * the image_info.
 *
 * \param[in]  fw_store  The subject fw_store
 * \param[in]  image_info  Image info that describes the image to install
 * \param[out] installer   Selected installer
 *
 * \return FWU status code
 */
int fw_store_select_installer(struct fw_store *fw_store, const struct image_info *image_info,
			      struct installer **installer);

/**
 * \brief Write image data during image installation
 *
 * \param[in]  fw_store  The subject fw_store
 * \param[in]  installer     The selected installer
 * \param[in]  data          Pointer to data
 * \param[in]  data_len      The data length
 *
 * \return FWU status code
 */
int fw_store_write_image(struct fw_store *fw_store, struct installer *installer,
			 const uint8_t *data, size_t data_len);

/**
 * \brief Commit image data
 *
 * Called after fw_store_write_image to commit all image data written for an image.
 *
 * \param[in]  fw_store   The subject fw_store
 * \param[in]  installer  The selected installer
 * \param[in]  image_info Info about the image
 * \param[in]  accepted   Initial accepted state
 *
 * \return FWU status code
 */
int fw_store_commit_image(struct fw_store *fw_store, struct installer *installer,
			  const struct image_info *image_info, bool accepted);

/**
 * \brief Notify that an updated image has been accepted
 *
 * \param[in]  fw_store    The subject fw_store
 * \param[in]  image_info  Information about the accepted image
 *
 * \return True if all necessary images have been accepted
 */
bool fw_store_notify_accepted(struct fw_store *fw_store, const struct image_info *image_info);

/**
 * \brief Check if image is accepted
 *
 * \param[in]  fw_store    The subject fw_store
 * \param[in]  image_info  Information about the image
 *
 * \return True if image has been accepted
 */
bool fw_store_is_accepted(const struct fw_store *fw_store, const struct image_info *image_info);

/**
 * \brief Check if the booted firmware is being trialed
 *
 * \param[in]  fw_store    The subject fw_store
 *
 * \return True if trialed
 */
bool fw_store_is_trial(const struct fw_store *fw_store);

/**
 * \brief Commit to the complete update
 *
 * \param[in]  fw_store  The subject fw_store
 *
 * \return FWU status code
 */
int fw_store_commit_to_update(struct fw_store *fw_store);

/**
 * \brief Revert back to the previous good version (if possible)
 *
 * \param[in]  fw_store    The subject fw_store
 *
 * \return FWU status code
 */
int fw_store_revert_to_previous(struct fw_store *fw_store);

/**
 * \brief Export fw_store specific objects
 *
 * Provides a way of exporting objects from a concrete fw_store e.g.
 * for coordinating with a Nwd client. A concrete fw_store may export
 * [0..*] types of object.
 *
 * \param[in]  fw_store    The subject fw_store
 * \param[in]  uuid        Identifies the object
 * \param[out] data		   Pointer to data to the exported object
 * \param[out] data_len    Length of the exported object
 * \param[out] status      Status of the export operation
 *
 * \return True if UUID identifies an object held by the fw_store
 */
bool fw_store_export(struct fw_store *fw_store, const struct uuid_octets *uuid,
		     const uint8_t **data, size_t *data_len, int *status);

#ifdef __cplusplus
}
#endif

#endif /* FW_STORE_H */
