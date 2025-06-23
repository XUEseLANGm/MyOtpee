/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "volume.h"

#include <errno.h>
#include <stddef.h>

void volume_init(struct volume *this_volume, const io_dev_funcs_t *io_dev_funcs,
		 uintptr_t concrete_volume)
{
	this_volume->dev_info.funcs = io_dev_funcs;
	this_volume->dev_info.info = concrete_volume;

	this_volume->dev_handle = (uintptr_t)&this_volume->dev_info;
	this_volume->io_spec = concrete_volume;

	this_volume->io_handle = 0;

	/* Optional functions that a concrete volume may provide */
	this_volume->erase = NULL;
	this_volume->get_storage_ids = NULL;
}

int volume_open(struct volume *this_volume)
{
	return io_open(this_volume->dev_handle, this_volume->io_spec, &this_volume->io_handle);
}

int volume_close(struct volume *this_volume)
{
	return io_close(this_volume->io_handle);
}

int volume_seek(struct volume *this_volume, io_seek_mode_t mode, signed long long offset)
{
	return io_seek(this_volume->io_handle, mode, offset);
}

int volume_size(struct volume *this_volume, size_t *size)
{
	return io_size(this_volume->io_handle, size);
}

int volume_read(struct volume *this_volume, uintptr_t buffer, size_t length, size_t *length_read)
{
	return io_read(this_volume->io_handle, buffer, length, length_read);
}

int volume_write(struct volume *this_volume, const uintptr_t buffer, size_t length,
		 size_t *length_written)
{
	return io_write(this_volume->io_handle, buffer, length, length_written);
}

int volume_erase(struct volume *this_volume)
{
	return (this_volume->erase) ? this_volume->erase(this_volume->dev_info.info) : 0;
}

int volume_get_storage_ids(struct volume *this_volume, struct uuid_octets *partition_guid,
			   struct uuid_octets *parent_guid)
{
	if (this_volume->get_storage_ids)
		return this_volume->get_storage_ids(this_volume->dev_info.info, partition_guid,
						    parent_guid);

	return -EIO;
}
