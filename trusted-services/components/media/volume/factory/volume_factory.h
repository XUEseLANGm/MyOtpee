/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_VOLUME_FACTORY_H
#define MEDIA_VOLUME_FACTORY_H

#include <stddef.h>

#include "common/uuid/uuid.h"
#include "media/volume/volume.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief  Initialise the singleton volume_factory
 *
 * Initialises the deployment specific volume factory. Once initialised, the volume_factory
 * will be ready to construct volume objects that can provide IO access to the requested
 * storage. The details of how the storage is accessed is hidden from the client. A set
 * of device UUIDs is returned, each identifying a storage device that can potentially be
 * accessed using a constructed volume.
 *
 * \param[out] device_uuids      Array of available device UUIDs
 * \param[in]  device_uuids_size Number of slots in the provided array
 * \param[out] num_device_uuids  The number of device UUIDs actually returned
 *
 * \return Status (0 on success)
 */
int volume_factory_init(struct uuid_octets *device_uuids, size_t device_uuids_size,
			size_t *num_device_uuids);

/**
 * \brief  De-initialises the volume_factory
 */
void volume_factory_deinit(void);

/**
 * \brief  Common interface for constructing volume objects
 *
 * The volume_factory provides a common interface for constructing volume objects,
 * decoupling client code from the details of initialising a concrete volume.
 * Volume objects created by the factory should also be destroyed by the factory.
 *
 * \param[in] partition_uuid  Identifies the unit of storage (e.g. a unique partition uuid)
 * \param[in] device_uuid     Identifies the parent device
 *
 * \return Pointer to volume or NULL
 */
struct volume *volume_factory_create_volume(const struct uuid_octets *partition_uuid,
					    const struct uuid_octets *device_uuid);

/**
 * \brief  Destroys a volume object
 *
 * \param[in] volume   Volume to destroy
 */
void volume_factory_destroy_volume(struct volume *volume);

#ifdef __cplusplus
}
#endif

#endif /* MEDIA_VOLUME_FACTORY_H */
