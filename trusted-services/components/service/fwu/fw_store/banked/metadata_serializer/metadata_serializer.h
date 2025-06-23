/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef METADATA_SERIALIZER_H
#define METADATA_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct fw_directory;
struct bank_tracker;

/**
 * \brief FWU metadata serializer interface
 *
 * Defines a common interface for FWU serialization operations. Because
 * updates to the bootloader and update agent are likely to occur at different
 * times, it is necessary for the update agent to have some agility over the
 * metadata version that it generates in order to maintain compatibility with
 * the bootloader. The active serializer is selected based on the version
 * reported by the bootloader at boot time. Note that the early stage bootloader
 * that interprets the metadata cannot be updated using the banked update
 * mechanism so it is not possible to rely on a simultaneous update strategy.
 * To provide a pathway for transitioning to a new metadata version,
 * support for runtime selection of the metadata serializer is possible.
 */
struct metadata_serializer {
	/**
	 * \brief Serialize FWU metadata
	 *
	 *  Serialize FWU metadata using the presented inputs.
	 *
	 * \param[in]  active_index   The active bank index
	 * \param[in]  previous_active_index    The previous active bank index
	 * \param[in]  fw_dir         Source firmware directory
	 * \param[in]  bank_tracker   source bank_tracker
	 * \param[in]  buf            Serialize into this buffer
	 * \param[in]  buf_size       Size of buffer
	 * \param[out] metadata_len   Size of serialized metadata
	 *
	 * \return Status
	 */
	int (*serialize)(uint32_t active_index, uint32_t previous_active_index,
			 const struct fw_directory *fw_dir, const struct bank_tracker *bank_tracker,
			 uint8_t *buf, size_t buf_size, size_t *metadata_len);

	/**
	 * \brief Return serialized FWU metadata size
	 *
	 * \param[in]  fw_dir         Source information
	 *
	 * \return Size in bytes
	 */
	size_t (*size)(const struct fw_directory *fw_dir);

	/**
	 * \brief Return the maximum serialized FWU metadata size
	 *
	 * \return Size in bytes
	 */
	size_t (*max_size)(void);

	/**
	 * \brief De-serialize bank info information
	 *
	 * \param[in]  bank_tracker Destination bank_tracker
	 * \param[in]  serialized_metadata  Serialized metadata
	 * \param[in]  metadata_len   Length of serialized metadata
	 */
	void (*deserialize_bank_info)(struct bank_tracker *bank_tracker,
				      const uint8_t *serialized_metadata, size_t metadata_len);

	/**
	 * \brief De-serialize active indices
	 *
	 * \param[out] active_index   active_index value
	 * \param[out] previous_active_index   previous_active_index value
	 * \param[in]  serialized_metadata  Serialized metadata
	 * \param[in]  metadata_len   Length of serialized metadata
	 */
	void (*deserialize_active_indices)(uint32_t *active_index, uint32_t *previous_active_index,
					   const uint8_t *serialized_metadata, size_t metadata_len);
};

#ifdef __cplusplus
}
#endif

#endif /* METADATA_SERIALIZER_H */
