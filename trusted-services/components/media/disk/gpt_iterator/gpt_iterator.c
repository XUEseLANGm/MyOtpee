/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "gpt_iterator.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "media/volume/volume.h"

int gpt_iterator_init(struct gpt_iterator *iter, struct volume *volume)
{
	assert(iter);
	assert(volume);

	iter->num_entries = 0;
	iter->entry_size = 0;
	iter->cur_index = 0;
	iter->volume = NULL;

	int status = volume_open(volume);

	if (status)
		return status;

	iter->volume = volume;

	status = volume_seek(volume, IO_SEEK_SET, GPT_HEADER_OFFSET);

	if (status)
		return status;

	gpt_header_t gpt_header;
	size_t bytes_read = 0;

	status = volume_read(volume, (uintptr_t)&gpt_header, sizeof(gpt_header), &bytes_read);

	if (status)
		return status;

	if (bytes_read != sizeof(gpt_header))
		return -EIO;

	/* Check that GPT header looks valid. It is assumed that the CRC will already been checked
	 * e.g. by the bootloader. The checks are intended to defend against either deliberate or
	 * accidental corruption of the header leading to use of unreasonable partition table
	 * attributes. The checks need to be tolerant to GPT version changes that result in a
	 * mismatch between this code's view of structures and the structure used when the GPT
	 * in the disk image was created. This could occur through firmware updates over the
	 * lifetime of the device. An assumption is that over time, GPT structures will only ever
	 * be extended and that all versions will share a common base structure. The check for an
	 * oversized partition entry puts a reasonable upper limit on the structure size as 2 *
	 * sizeof(gpt_entry_t). This relies on there never being a 2x size mismatch over the
	 * lifetime of the device.
	 */
	size_t min_required_entry_size =
		offsetof(gpt_entry_t, name) + EFI_NAMELEN * sizeof(unsigned short);
	size_t max_expected_entry_size = sizeof(gpt_entry_t) * 2;

	if ((memcmp(GPT_SIGNATURE, gpt_header.signature, sizeof(gpt_header.signature)) != 0) ||
	    gpt_header.part_size < min_required_entry_size ||
	    gpt_header.part_size > max_expected_entry_size || iter->num_entries > 128)
		return -EIO;

	iter->num_entries = gpt_header.list_num;
	iter->entry_size = gpt_header.part_size;

	return 0;
}

void gpt_iterator_deinit(struct gpt_iterator *iter)
{
	assert(iter);

	if (iter->volume)
		volume_close(iter->volume);
}

void gpt_iterator_first(struct gpt_iterator *iter)
{
	assert(iter);

	iter->cur_index = 0;
}

void gpt_iterator_next(struct gpt_iterator *iter)
{
	assert(iter);

	++iter->cur_index;
}

bool gpt_iterator_is_done(const struct gpt_iterator *iter)
{
	assert(iter);

	return (iter->cur_index >= iter->num_entries);
}

int gpt_iterator_current(struct gpt_iterator *iter, gpt_entry_t *entry)
{
	assert(iter);
	assert(iter->volume);
	assert(!gpt_iterator_is_done(iter));

	size_t bytes_read = 0;
	size_t cur_pos = iter->cur_index * iter->entry_size + GPT_ENTRY_OFFSET;
	int status = volume_seek(iter->volume, IO_SEEK_SET, cur_pos);

	if (status)
		return status;

	status = volume_read(iter->volume, (uintptr_t)entry, sizeof(gpt_entry_t), &bytes_read);

	if (status)
		return status;

	if (bytes_read != sizeof(gpt_entry_t))
		return -EIO;

	return 0;
}
