/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_BLOCK_STORAGE_PACKEDC_MESSAGES_H
#define TS_BLOCK_STORAGE_PACKEDC_MESSAGES_H

#include <stdint.h>

/**
 * Protocol definitions for block storage operations
 * using the packed-c serialization.
 */

/****************************************
 * Common defines
 */
#define TS_BLOCK_STORAGE_GUID_OCTET_LEN   (16)

/****************************************
 * \brief get_partition_info operation
 *
 * Get information about the storage partition identified by the specified
 * unique partition GUID.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_block_storage_get_partition_info_in
{
	uint8_t partition_guid[TS_BLOCK_STORAGE_GUID_OCTET_LEN];
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_block_storage_get_partition_info_out
{
	uint64_t num_blocks;
	uint32_t block_size;
	uint8_t partition_guid[TS_BLOCK_STORAGE_GUID_OCTET_LEN];
	uint8_t parent_guid[TS_BLOCK_STORAGE_GUID_OCTET_LEN];
};

/****************************************
 * \brief open operation
 *
 * Open the storage partition identified by the specified unique partition
 * GUID. A handle is returned that should be used as a qualifier for subsequent
 * partition-oriented operations.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_block_storage_open_in
{
	uint8_t partition_guid[TS_BLOCK_STORAGE_GUID_OCTET_LEN];
};

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_block_storage_open_out
{
	uint64_t handle;
};

/****************************************
 * \brief close operation
 *
 * Close a previously opened storage partition. Used when access to the storage
 * partition is no longer required.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_block_storage_close_in
{
	uint64_t handle;
};

/****************************************
 * \brief read operation
 *
 * Read data from the block identified by the specified LBA.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_block_storage_read_in
{
	uint64_t handle;
	uint64_t lba;
	uint32_t offset;
	uint32_t len;
};

/* Read data returned in response */

/****************************************
 * \brief write operation
 *
 * Write data to the block identified by the specified LBA.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_block_storage_write_in
{
	uint64_t handle;
	uint64_t lba;
	uint32_t offset;
};

/* Write data follows fixed size input message */

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_block_storage_write_out
{
	uint64_t num_written;
};

/****************************************
 * \brief erase operation
 *
 * Erase the set of blocks identified by the specified set of LBAs.
 */

/* Mandatory fixed sized input parameters */
struct __attribute__ ((__packed__)) ts_block_storage_erase_in
{
	uint64_t handle;
	uint64_t begin_lba;
	uint32_t num_blocks;
};

#endif /* TS_BLOCK_STORAGE_PACKEDC_MESSAGES_H */
