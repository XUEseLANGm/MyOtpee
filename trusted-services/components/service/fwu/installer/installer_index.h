/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef INSTALLER_INDEX_H
#define INSTALLER_INDEX_H

#include <stddef.h>
#include <stdint.h>

#include "service/fwu/agent/install_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct installer;
struct uuid_octets;

/**
 * @brief  Initialize the installer index
 *
 * The installer_index is a singleton that holds the set of installers that are suitable
 * for the deployment. The mix of installers will depend on factors such as the image
 * container used by firmware or whether images are encrypted etc.
 */
void installer_index_init(void);

/**
 * @brief  Clears the installer index
 *
 * Clears all mappings.
 */
void installer_index_clear(void);

/**
 * @brief  Register an installer
 *
 * Registers an installer to handle image installation for a particular install_type
 * and location.
 *
 * @param[in] installer      The installer to use
 */
void installer_index_register(struct installer *installer);

/**
 * @brief  Find an installer for the specified type and location
 *
 * @param[in]  install_type  The type of installer
 * @param[in]  location_id   The location it serves
 *
 * @return Pointer to a concrete installer or NULL if none found
 */
struct installer *installer_index_find(enum install_type install_type, uint32_t location_id);

/**
 * @brief  Find a registered installer associated with the specified location UUID
 *
 * @param[in]  location_uuid  The associated location UUID
 *
 * @return Pointer to a concrete installer or NULL if none found
 */
struct installer *installer_index_find_by_location_uuid(const struct uuid_octets *location_uuid);

/**
 * @brief  Iterator function
 *
 * @param[in]  index  0..n
 *
 * @return Pointer to a concrete installer or NULL if iterated beyond final entry
 */
struct installer *installer_index_get(unsigned int index);

/**
 * @brief  Get an array of location_ids
 *
 * Updatable firmware may be distributed over multiple locations. Each location is
 * assigned a location_id when the set of installers are registered for the platform.
 * This function returns a variable length array of locations_ids for the platform.
 * This is useful for checking if an incoming update has included components that
 * update all locations or not.
 *
 * @param[out]  num_ids  0..n
 *
 * @return Pointer to a static array of location ids
 */
const uint32_t *installer_index_get_location_ids(size_t *num_ids);

#ifdef __cplusplus
}
#endif

#endif /* INSTALLER_INDEX_H */
