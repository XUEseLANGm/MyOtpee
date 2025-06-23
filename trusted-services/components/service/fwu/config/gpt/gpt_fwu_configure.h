/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef GPT_FWU_CONFIGURE_H
#define GPT_FWU_CONFIGURE_H

#include "common/uuid/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief GPT based FWU configure method
 *
 * An FWU configuration comprises a set of installers and volume objects that
 * enables all updatable firmware images to be updated by the update agent. This
 * configure method uses partition information contained within a UEFI formatted
 * storage device to extend the FWU configuration to cover all updatable partitions
 * on the device. The configurator iterates over the GPT and progressively adds
 * the necessary installers and volumes to the configuration. To allow for multiple
 * configuration steps (e.g. for multiple devices), the initial location ID is
 * passed as a parameter and a count of the number of locations added is returned.
 *
 * \param[in] device_uuid   Identifies the target device
 * \param[in] initial_location_id Initial location ID
 * \param[out] location_count The number of locations added
 *
 * \return Status code (0 for success)
 */
int gpt_fwu_configure(const struct uuid_octets *device_uuid, unsigned int initial_location_id,
		      unsigned int *location_count);

#ifdef __cplusplus
}
#endif

#endif /* GPT_FWU_CONFIGURE_H */
