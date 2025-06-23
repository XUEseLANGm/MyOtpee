/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FWU_CONFIGURE_H
#define FWU_CONFIGURE_H

#include "common/uuid/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Configure installers and volumes for FWU
 *
 * Creates an FWU configuration consisting of a set of installers and volumes
 * that provide the capabilities needed to update images residing on the set
 * of storage devices identified by the input set of device UUIDs. Created
 * installers are added to the singleton installer_index and created volumes
 * are added to the volume_index. Related installers and volumes are grouped
 * by assigning location IDs.
 *
 * \param[in] device_uuids     Array of device UUIDs
 * \param[in] num_device_uuids Number of UUIDs in the array
  *
 * \return Configuration status (0 for success)
 */
int fwu_configure(const struct uuid_octets *device_uuids, size_t num_device_uuids);

/**
 * \brief De-configure the FWU configuration
 *
 * Deregisters and destroys all installers and volumes.
 */
void fwu_deconfigure(void);

#ifdef __cplusplus
}
#endif

#endif /* FWU_CONFIGURE_H */
