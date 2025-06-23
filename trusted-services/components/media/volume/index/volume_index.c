/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "volume_index.h"

#ifndef VOLUME_INDEX_MAX_ENTRIES
#define VOLUME_INDEX_MAX_ENTRIES		(8)
#endif

/**
 * Singleton index of volume IDs to IO devices.
 */
static struct {

	size_t size;
	struct {
		unsigned int volume_id;
		struct volume *volume;
	} entries[VOLUME_INDEX_MAX_ENTRIES];

} volume_index;

/**
 * @brief  Gets a device for volume IO operations
 *
 * @param[in]  volume_id 	Identifies the image
 * @param[out] dev_handle 	Handle for IO operations
 * @param[out] io_spec	Opaque configuration data
 *
 * This function realizes the interface expected by tf-a components to
 * provide a concrete IO device for the specified volume ID. When used in
 * TS deployments, the set of IO devices required for a deployment
 * are registered during service configuration.
 */
int plat_get_image_source(
	unsigned int volume_id,
	uintptr_t *dev_handle,
	uintptr_t *io_spec)
{
	struct volume *volume = NULL;
	int result = volume_index_find(volume_id, &volume);

	if (result == 0) {

		if (volume) {

			*dev_handle = volume->dev_handle;
			*io_spec = volume->io_spec;
		} else
			result = -1;
	}

	return result;
}

void volume_index_init(void)
{
	volume_index_clear();
}

void volume_index_clear(void)
{
	memset(&volume_index, 0, sizeof(volume_index));
}

int volume_index_add(
	unsigned int volume_id,
	struct volume *volume)
{
	int result = -1;

	if (volume_index.size < VOLUME_INDEX_MAX_ENTRIES) {
		size_t i = volume_index.size;

		++volume_index.size;
		volume_index.entries[i].volume_id = volume_id;
		volume_index.entries[i].volume = volume;

		result = 0;
	}

	return result;
}

int volume_index_find(
	unsigned int volume_id,
	struct volume **volume)
{
	int result = -1;

	for (size_t i = 0; i < volume_index.size; i++) {

		if (volume_index.entries[i].volume_id == volume_id) {

			*volume = volume_index.entries[i].volume;
			result = 0;
			break;
		}
	}

	return result;
}

struct volume *volume_index_get(unsigned int index)
{
	struct volume *volume = NULL;

	if (index < volume_index.size)
		volume = volume_index.entries[index].volume;

	return volume;
}
