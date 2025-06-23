/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BANKED_FW_STORE_VOLUME_ID_H
#define BANKED_FW_STORE_VOLUME_ID_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Storage volume IDs used by a banked_fw_store.
 *
 * These IDs are used to obtain deployment specific volume objects from
 * the volume_index to enable storage IO operations to be performed. Use
 * of volume IDs allows generic components to be decoupled from deployment
 * specific code. A set of volume objects will be constructed for a deployment,
 * each configured to provide access to each area of storage that holds
 * NV data that will be modified during the FWU process.
 *
 * To allow images to be installed into different storage locations (e.g.
 * different storage partitions), a volume ID numbering scheme is used for
 * the banked_fw_store that combines a location ID with usage ID.
 */

/* FWU metadata volume IDs. A single location is assumed. */
#define BANKED_VOLUME_ID_PRIMARY_METADATA (0xffff0000)
#define BANKED_VOLUME_ID_BACKUP_METADATA  (0xffff0001)

/* Per-location usage IDs for the banked_fw store */
#define BANKED_USAGE_ID_FW_BANK_A (0)
#define BANKED_USAGE_ID_FW_BANK_B (1)

/**
 * \brief Return a volume id constructed from a usage and location id
 *
 * Banked storage may be distributed across multiple locations. This
 * function creates a volume ID made up of a location ID and a usage ID.
 * A platform integrator is free define as many location IDs as is
 * necessary to enable different areas of firmware storage to be
 * updated. A location could correspond to say a storage partition or
 * storage managed by a separate MCU.
 *
 * \param[in]  location_id    Platform specific location id
 * \param[in]  usage_id       The requires usage for the volume
 *
 * \return volume id
 */
static inline unsigned int banked_volume_id(unsigned int location_id, unsigned int usage_id)
{
	return (location_id << 16) | (usage_id & 0xffff);
}

/**
 * \brief Return the usage id for the specified bank index
 *
 * \param[in]  bank_index    The bank index [0..1]
 *
 * \return Usage ID
 */
static inline unsigned int banked_usage_id(unsigned int bank_index)
{
	return (bank_index == 0) ? BANKED_USAGE_ID_FW_BANK_A : BANKED_USAGE_ID_FW_BANK_B;
}

#ifdef __cplusplus
}
#endif

#endif /* BANKED_FW_STORE_VOLUME_ID_H */
