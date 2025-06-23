/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <media/volume/index/volume_index.h>
#include <media/volume/base_io_dev/base_io_dev.h>
#include "disk_formatter.h"

int disk_formatter_clone(
	uintptr_t dev_handle,
	uintptr_t io_spec,
	const uint8_t *source_image,
	size_t source_image_size)
{
	uintptr_t volume_handle;
	int result;

	result = io_open(dev_handle, io_spec, &volume_handle);
	if (result != 0)
		return result;

	result = io_seek(volume_handle, IO_SEEK_SET, 0);

	if (result == 0) {

		size_t length_written = 0;

		result = io_write(volume_handle,
			(const uintptr_t)source_image,
			source_image_size,
			&length_written);
	}

	io_close(volume_handle);
	return result;
}