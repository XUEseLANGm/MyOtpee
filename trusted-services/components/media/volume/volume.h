/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_VOLUME_H
#define MEDIA_VOLUME_H

#include <stddef.h>

#include "common/uuid/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Export tf-a version with C++ linkage support.
 */
#include <drivers/io/io_driver.h>
#include <drivers/io/io_storage.h>

/**
 * A volume can be used to access storage as a single seekable volume
 * that may be accessed using file io type operations. The base volume
 * extends the TF-A io_dev to add an erase operation to enable the entire
 * volume to be erased prior to performing write operations. This is useful
 * when doing things like installing firmware into a raw disk partition.
 * Alternative concrete volume implementations are possible to suite different
 * classes of storage. If a concrete volume does not support erase, the
 * erase function pointer may be set to NULL;
 */
struct volume {
	/* IO device handle for volume access */
	uintptr_t dev_handle;

	/* Opaque IO spec */
	uintptr_t io_spec;

	/* Base IO device */
	io_dev_info_t dev_info;

	/* Handle for IO operations */
	uintptr_t io_handle;

	/* Optional function to erase the volume */
	int (*erase)(uintptr_t context);

	/* Optional function to get storage IDs for the volume */
	int (*get_storage_ids)(uintptr_t context, struct uuid_octets *partition_guid,
			       struct uuid_octets *parent_guid);
};

/**
 * @brief  Initialize the base volume structure
 *
 * Called by a concrete volume to initialize the base volume and io_dev.
 *
 * @param[in] this_volume    The subject volume
 * @param[in] io_dev_funcs   io_dev function struct for concrete handlers
 * @param[in] concrete_volume Pointer to the concrete volume instance
 */
void volume_init(struct volume *this_volume, const io_dev_funcs_t *io_dev_funcs,
		 uintptr_t concrete_volume);

/**
 * @brief  Open the volume for IO operations
 *
 * @param[in] this_volume    The subject volume
 *
 * @return 0 on success
 */
int volume_open(struct volume *this_volume);

/**
 * @brief  Close the volume when done with IO operations
 *
 * @param[in] this_volume    The subject volume
 *
 * @return 0 on success
 */
int volume_close(struct volume *this_volume);

/**
 * @brief  Seek to the specified position
 *
 * @param[in] this_volume    The subject volume
 * @param[in] mode   See io_storage.h for options
 * @param[in] offset Seek offset
 *
 * @return 0 on success
 */
int volume_seek(struct volume *this_volume, io_seek_mode_t mode, signed long long offset);

/**
 * @brief  Get the size of the volume
 *
 * @param[in] this_volume    The subject volume
 * @param[out] size   Size in bytes of the volume
 *
 * @return 0 on success
 */
int volume_size(struct volume *this_volume, size_t *size);

/**
 * @brief  Read from the volume
 *
 * Reads from the current seek position.
 *
 * @param[in] this_volume    The subject volume
 * @param[in] buffer   Buffer to put read data
 * @param[in] length   Requested read length
 * @param[out] length_read Actual length read
 *
 * @return 0 on success
 */
int volume_read(struct volume *this_volume, uintptr_t buffer, size_t length, size_t *length_read);

/**
 * @brief  Write the volume
 *
 * Write from the current seek position.
 *
 * @param[in] this_volume    The subject volume
 * @param[in] buffer   Buffer containing data to write
 * @param[in] length   Requested write length
 * @param[out] length_read Actual write read
 *
 * @return 0 on success
 */
int volume_write(struct volume *this_volume, const uintptr_t buffer, size_t length,
		 size_t *length_written);

/**
 * @brief  Erase the entire volume
 *
 * @param[in] this_volume    The subject volume
 *
 * @return 0 on success
 */
int volume_erase(struct volume *this_volume);

/**
 * @brief  Get GUIDs to identify the storage associated with the volume
 *
 * If supported by a concrete volume
 *
 * @param[in] this_volume    The subject volume
 * @param[out] partition_guid GUID for the logical partition
 * @param[out] parent_guid GUID for a parent device e.g. a disk GUID
 *
 * @return 0 on success, ENOSYS if not supported
 */
int volume_get_storage_ids(struct volume *this_volume, struct uuid_octets *partition_guid,
			   struct uuid_octets *parent_guid);

#ifdef __cplusplus
}
#endif

#endif /* MEDIA_VOLUME_H */
