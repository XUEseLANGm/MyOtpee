/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_DISK_FORMATTER_H
#define MEDIA_DISK_FORMATTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Format a storage volume by cloning a disk image
 *
 * @param[in] dev_handle    IO device handle
 * @param[in] io_spec   Opaque volume spec
 * @param[in] source_image  The source disk image to clone
 * @param[in] source_image_size  The size of the source image
 *
 * @return 0 on success
 */
int disk_formatter_clone(
	uintptr_t dev_handle,
	uintptr_t io_spec,
	const uint8_t *source_image,
	size_t source_image_size);

#ifdef __cplusplus
}
#endif

#endif /* MEDIA_DISK_FORMATTER_H */
