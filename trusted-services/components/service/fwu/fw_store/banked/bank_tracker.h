/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BANK_TRACKER_H
#define BANK_TRACKER_H

#include <stdbool.h>

#include "bank_scheme.h"
#include "service/fwu/agent/fw_directory.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief bank_tracker structure definition
 *
 * Tracks the state of fw_store banks.
 */
struct bank_tracker {
	struct {
		/* True if bank holds content */
		bool is_content;

		/* Image accepted state for images contained in the bank */
		bool is_accepted[FWU_MAX_FW_DIRECTORY_ENTRIES];

	} bank_state[BANK_SCHEME_NUM_BANKS];
};

/**
 * \brief Initialize the bank_tracker
 *
 * \param[in] subject       This instance
 */
void bank_tracker_init(struct bank_tracker *subject);

/**
 * \brief De-initialize the bank_tracker
 *
 * \param[in] subject      This instance
 */
void bank_tracker_deinit(struct bank_tracker *subject);

/**
 * \brief Mark image as accepted
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 * \param[in] image_index  The image index (from fw_directory)
 */
void bank_tracker_accept(struct bank_tracker *subject, unsigned int bank_index,
			 unsigned int image_index);

/**
 * \brief Copy image accept state
 *
 * \param[in] subject      This instance
 * \param[in] from_bank_index Copy accepted state from bank index
 * \param[in] to_bank_index Copy accepted state to bank index
 * \param[in] image_index  The image index (from fw_directory)
 */
void bank_tracker_copy_accept(struct bank_tracker *subject, unsigned int from_bank_index,
			      unsigned int to_bank_index, unsigned int image_index);

/**
 * \brief Sets bank as holding no content
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 */
void bank_tracker_set_no_content(struct bank_tracker *subject, unsigned int bank_index);

/**
 * \brief Set bank as holding content
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 */
void bank_tracker_set_holds_content(struct bank_tracker *subject, unsigned int bank_index);

/**
 * \brief Set bank as holding fully accepted content
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 */
void bank_tracker_set_holds_accepted_content(struct bank_tracker *subject, unsigned int bank_index);

/**
 * \brief Check if bank holds contents
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 *
 * \return True if bank holds content
 */
bool bank_tracker_is_content(const struct bank_tracker *subject, unsigned int bank_index);

/**
 * \brief Check if image is accepted
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 * \param[in] image_index  The image index
 *
 * \return True if an image has been accepted
 */
bool bank_tracker_is_accepted(const struct bank_tracker *subject, unsigned int bank_index,
			      unsigned int image_index);

/**
 * \brief Check if all images are accepted
 *
 * \param[in] subject      This instance
 * \param[in] bank_index   The firmware bank
 * \param[in] num_images   Number of images to consider
 *
 * \return True if all images have been accepted
 */
bool bank_tracker_is_all_accepted(const struct bank_tracker *subject, unsigned int bank_index,
				  unsigned int num_images);

#ifdef __cplusplus
}
#endif

#endif /* BANK_TRACKER_H */
