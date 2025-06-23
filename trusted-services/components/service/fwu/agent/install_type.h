/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INSTALL_TYPE_H
#define INSTALL_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief A classifier for the type of installation performed by an installer
 *
 * The scope of an update image may encompass the whole contents of a storage
 * volume or just a part of the volume. The install_type is used to help
 * associate an incoming image with an appropriate installer.
 */
enum install_type {

	/* An installer that updates the entire contents of a storage volume.
	 * This type of installer doesn't need to understand the installed
	 * image format and can just install directly into a storage volume.
	 */
	INSTALL_TYPE_WHOLE_VOLUME,

	/* An installer that updates a part of a storage volume. To achieve
	 * this, the installer must have knowledge of the format of the target
	 * storage volume.
	 */
	INSTALL_TYPE_SUB_VOLUME,

	/* An installer that copies the entire contents of one volume to
	 * another. No externally provided update data is installed. When
	 * a platform with multiple locations receives an update that only
	 * updates some locations, a whole volume copy installer can be used
	 * to duplicate the active bank contents into the update bank.
	 */
	INSTALL_TYPE_WHOLE_VOLUME_COPY,

	INSTALL_TYPE_LIMIT
};

#ifdef __cplusplus
}
#endif

#endif /* INSTALL_TYPE_H */
