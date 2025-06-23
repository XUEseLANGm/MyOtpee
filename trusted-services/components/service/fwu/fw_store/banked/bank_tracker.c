/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "bank_tracker.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

void bank_tracker_init(struct bank_tracker *subject)
{
	memset(subject, 0, sizeof(struct bank_tracker));
}

void bank_tracker_deinit(struct bank_tracker *subject)
{
	(void)subject;
}

void bank_tracker_accept(struct bank_tracker *subject, unsigned int bank_index,
			 unsigned int image_index)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);
	assert(image_index < FWU_MAX_FW_DIRECTORY_ENTRIES);

	subject->bank_state[bank_index].is_accepted[image_index] = true;
}

void bank_tracker_copy_accept(struct bank_tracker *subject, unsigned int from_bank_index,
			      unsigned int to_bank_index, unsigned int image_index)
{
	assert(from_bank_index < BANK_SCHEME_NUM_BANKS);
	assert(to_bank_index < BANK_SCHEME_NUM_BANKS);
	assert(image_index < FWU_MAX_FW_DIRECTORY_ENTRIES);

	subject->bank_state[to_bank_index].is_accepted[image_index] =
		subject->bank_state[from_bank_index].is_accepted[image_index];
}

void bank_tracker_set_no_content(struct bank_tracker *subject, unsigned int bank_index)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);

	subject->bank_state[bank_index].is_content = false;

	for (unsigned int i = 0; i < FWU_MAX_FW_DIRECTORY_ENTRIES; i++)
		subject->bank_state[bank_index].is_accepted[i] = false;
}

void bank_tracker_set_holds_content(struct bank_tracker *subject, unsigned int bank_index)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);

	subject->bank_state[bank_index].is_content = true;
}

void bank_tracker_set_holds_accepted_content(struct bank_tracker *subject, unsigned int bank_index)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);

	subject->bank_state[bank_index].is_content = true;

	for (unsigned int i = 0; i < FWU_MAX_FW_DIRECTORY_ENTRIES; i++)
		subject->bank_state[bank_index].is_accepted[i] = true;
}

bool bank_tracker_is_content(const struct bank_tracker *subject, unsigned int bank_index)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);

	return subject->bank_state[bank_index].is_content;
}

bool bank_tracker_is_accepted(const struct bank_tracker *subject, unsigned int bank_index,
			      unsigned int image_index)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);
	assert(image_index < FWU_MAX_FW_DIRECTORY_ENTRIES);

	return subject->bank_state[bank_index].is_accepted[image_index];
}

bool bank_tracker_is_all_accepted(const struct bank_tracker *subject, unsigned int bank_index,
				  unsigned int num_images)
{
	assert(bank_index < BANK_SCHEME_NUM_BANKS);
	assert(num_images <= FWU_MAX_FW_DIRECTORY_ENTRIES);

	for (unsigned int image_index = 0; image_index < num_images; image_index++) {
		if (!subject->bank_state[bank_index].is_accepted[image_index])
			return false;
	}

	return true;
}
