/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef GPT_ITERATOR_H
#define GPT_ITERATOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

//This seems to be missing from TF-A:tf-a-src/include/tools_share/uuid.h
#include <stdint.h>
/**
 * Export tf-a version with C++ linkage support.
 */
#include <drivers/partition/gpt.h>

/**
 * Interface dependencies
 */
struct volume;

/**
 * \brief gpt_iterator structure definition
 *
 * Holds state while iterating over partition table entries
 */
struct gpt_iterator {
	unsigned int num_entries;
	unsigned int entry_size;
	unsigned int cur_index;

	struct volume *volume;
};

/**
 * \brief Initialize the iterator
 *
 * Initializes a gpt_iterator in preparation for use. The provided volume
 * should provide access to the storage device/partition that contains the
 * MBR/GPT at the start of the volume. The integrity of the GPT should have
 * already been verified before using this iterator. The volume must be
 * initially closed. It will be opened on init and closed on deinit.
 *
 * \param[in]  iter      The subject gpt_iterator
 * \param[in]  volume    Volume containing the MBR/GPT
 *
 * \return IO Status code (0 for success)
 */
int gpt_iterator_init(struct gpt_iterator *iter, struct volume *volume);

/**
 * \brief De-initialize the iterator
 *
 * \param[in]  iter      The subject gpt_iterator
 */
void gpt_iterator_deinit(struct gpt_iterator *iter);

/**
 * \brief Set iterator position to first partition entry
 *
 * \param[in]  iter      The subject gpt_iterator
 */
void gpt_iterator_first(struct gpt_iterator *iter);

/**
 * \brief Iterate to the next entry
 *
 * \param[in]  iter      The subject gpt_iterator
 */
void gpt_iterator_next(struct gpt_iterator *iter);

/**
 * \brief Returns true if iterated beyond final entry
 *
 * \param[in]  iter      The subject gpt_iterator
 */
bool gpt_iterator_is_done(const struct gpt_iterator *iter);

/**
 * \brief Returns the partition entry at the current iterator position
 *
 * \param[in]  iter      The subject gpt_iterator
 * \param[out] entry     Copied to this structure
 *
 * \return IO Status code (0 for success)
 */
int gpt_iterator_current(struct gpt_iterator *iter, gpt_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif /* GPT_ITERATOR_H */
