/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef INSTALLER_FACTORY_H
#define INSTALLER_FACTORY_H

#include "common/uuid/uuid.h"
#include "service/fwu/agent/install_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct installer;

/**
 * \brief  An interface for constructing image installers
 *
 * The FWU update service can be used to install a diverse range of firmware images. To
 * allow for platform specific installers that handle different image formats and installation
 * methods, a common interface is used for constructing concrete installers. The implementation
 * of the installer_factory determines the set of concrete installers that are available
 * in a deployment. It is envisaged that alternative factory implementations will be needed
 * to cater for different classes of product with different installation requirements. A
 * constructed installer should be destroyed using the installer_factory_destroy_installer
 * method when the installer is no longer needed.
 *
 * \param[in] installation_type The type of installation required
 * \param[in] location_id     The short location_id that corresponds to the location_uuid
 * \param[in] location_uuid   UUID to identify the location into which images will be installed
 *
 * \return The constructed installer or NULL if no suitable installer can be constructed.
 */
struct installer *installer_factory_create_installer(enum install_type installation_type,
						     unsigned int location_id,
						     const struct uuid_octets *location_uuid);

/**
 * \brief  Destroy an installer
 *
 * \param[in] installer     Installer to destroy
 */
void installer_factory_destroy_installer(struct installer *installer);

#ifdef __cplusplus
}
#endif

#endif /* INSTALLER_FACTORY_H */
