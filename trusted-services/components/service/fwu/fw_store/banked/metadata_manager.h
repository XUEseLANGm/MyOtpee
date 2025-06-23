/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef METADATA_MANAGER_H
#define METADATA_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct volume;
struct fw_directory;
struct bank_tracker;
struct metadata_serializer;

/**
 * \brief metadata_manager structure definition
 *
 * Manages the FWU metadata seen by the boot loader.
 */
struct metadata_manager {
	/* Volume objects for IO operations to NV storage */
	struct volume *primary_metadata_volume;
	struct volume *backup_metadata_volume;

	/* Metadata serializer compatible with bootloader */
	const struct metadata_serializer *serializer;

	/* Cached copy of metadata */
	bool is_dirty;
	bool is_valid;
	uint32_t stored_crc;
	size_t metadata_len;
	size_t metadata_max_len;
	uint8_t *metadata_cache;
};

/**
 * \brief Initialize the metadata_manager
 *
 * \param[in] subject       This instance
 * \param[in] serializer    Metadata serializer to use
 *
 * \return Status 0 on success
 */
int metadata_manager_init(struct metadata_manager *subject,
			  const struct metadata_serializer *serializer);

/**
 * \brief De-initialize the metadata_manager
 *
 * \param[in] subject      This instance
 */
void metadata_manager_deinit(struct metadata_manager *subject);

/**
 * \brief Check integrity of FWU metadata and repair if necessary
 *
 * FWU metadata is vulnerable to corruption due to power failure during a
 * write to storage. To mitigate this risk, a replica is maintained which
 * the boot loader will use if necessary. When a corruption occurs, the
 * corrupted copy is repaired by copying the intact replica. Returns
 * failure if a repair was not possible.
 *
 * \param[in] subject      This instance
 * \param[in] fw_dir       The fw_directory
 *
 * \return Status 0 if intact or if repair was successful
 */
int metadata_manager_check_and_repair(struct metadata_manager *subject,
				      const struct fw_directory *fw_dir);

/**
 * \brief Update the FWU metadata seen by the boot loader
 *
 * \param[in]  subject        This instance
 * \param[in]  active_index   The active bank index
 * \param[in]  previous_active_index    The previous active bank index
 * \param[in]  fw_dir         Source firmware directory
 * \param[in]  bank_tracker   Provides bank state
 *
 * \return Status 0 if successful
 */
int metadata_manager_update(struct metadata_manager *subject, uint32_t active_index,
			    uint32_t previous_active_index, const struct fw_directory *fw_dir,
			    const struct bank_tracker *bank_tracker);

/**
 * \brief Get the active index values from the metadata
 *
 * \param[in]  subject        This instance
 * \param[out] active_index   The active bank index
 * \param[out] previous_active_index   The previous active bank index
 *
 * \return Status 0 if successful
 */
int metadata_manager_get_active_indices(const struct metadata_manager *subject,
					uint32_t *active_index, uint32_t *previous_active_index);

/**
 * \brief Fetch the FWU metadata that should be seen by the boot loader
 *
 * In deployments where the metadata manager is unable to update the metadata
 * seen by the boot loader directly, this function outputs the most recently
 * updated view of the metadata to enable a Nwd component to perform the necessary
 * write to storage.
 *
 * \param[in]  subject   This instance
 * \param[out] data      Outputs pointer to data
 * \param[out] data_len  Length of metadata
 * \param[out] is_dirty  True if updated since previous call
 *
 * \return Status 0 if successful
 */
int metadata_manager_fetch(struct metadata_manager *subject, const uint8_t **data, size_t *data_len,
			   bool *is_dirty);

/**
 * \brief Invalidate the metadata cache
 *
 * \param[in]  subject   This instance
 */
void metadata_manager_cache_invalidate(struct metadata_manager *subject);

/**
 * \brief Preload the bank_tracker with NV state from metadata
 *
 * \param[in]  subject   This instance
 * \param[in]  bank_tracker  The bank_tracker to modify
 *
 * \return Status 0 if successful
 */
void metadata_manager_preload_bank_tracker(const struct metadata_manager *subject,
					   struct bank_tracker *bank_tracker);

#ifdef __cplusplus
}
#endif

#endif /* METADATA_MANAGER_H */
