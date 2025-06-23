/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_VOLUME_INDEX_H
#define MEDIA_VOLUME_INDEX_H

#include <stdint.h>
#include <media/volume/volume.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * For tf-a declaration of plat_get_image_source(). Included within C++ extern C
 * guard to allow for calling from C++.
 */
#include <plat/common/platform.h>

/**
 * @brief  Some common volume identifiers
 *
 * Volume IDs only need to be unique within a deployment. For convenience,
 * here are some common volume IDs that may be useful.
 */
#define VOLUME_ID_COMMON_BASE        (0x10000000)
#define VOLUME_ID_SECURE_FLASH       (VOLUME_ID_COMMON_BASE + 0)

/**
 * @brief  Initialize the volume index
 *
 * The volume_index is a singleton that holds the mapping of volume IDs
 * to concrete volume objects that associate a storage volume with an
 * IO device that may be used to access storage. The mappings are setup
 * during deployment configuration to meet the IO needs of the deployment.
 * The volume_index realizes the tf-a function plat_get_image_source() to
 * make the mappings available to tf-a components.
 */
void volume_index_init(void);

/**
 * @brief  Clears the volume index
 *
 * Clears all mappings.
 */
void volume_index_clear(void);

/**
 * @brief  Add an entry to the volume index
 *
 * @param[in] volume_id   Volume identifier
 * @param[in] volume      The volume that extends the base io_dev
 *
 * @return 0 if successful
 */
int volume_index_add(
	unsigned int volume_id,
	struct volume *volume);

/**
 * @brief  Find an added volume by volume index
 *
 * @param[in]  volume_id   Volume identifier
 * @param[out] volume      The volume that extends the base io_dev
 *
 * @return 0 if found
 */
int volume_index_find(
	unsigned int volume_id,
	struct volume **volume);

/**
 * @brief  Iterator function
 *
 * @param[in]  index  0..n
 *
 * @return Pointer to a concrete volume or NULL if iterated beyond final entry
 */
struct volume *volume_index_get(unsigned int index);


#ifdef __cplusplus
}
#endif

#endif /* MEDIA_VOLUME_INDEX_H */
