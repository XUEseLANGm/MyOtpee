/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef STORAGE_PARTITION_H
#define STORAGE_PARTITION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "common/uuid/uuid.h"
#include "storage_partition_acl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Common storage partition structure
 *
 * A block store may present one or more storage partitions. This structure may
 * be used by concrete block_store implementations to describe a storage partition
 * in a generic way.
 */
struct storage_partition
{
	/* Unique partition GUID */
	struct uuid_octets partition_guid;

	/* Block size in bytes */
	size_t block_size;

	/* The number of contiguous blocks from LBA zero */
	size_t num_blocks;

	/* Backend storage block that corresponds to LBA zero */
	uint64_t base_lba;

	/* Access control list for controlling access to configured owner */
	struct storage_partition_acl acl;
};

/**
 * \brief Default storage_partition initialization function
 *
 * Initializes a storage_partition with a one-to-one LBA mapping to backend
 * storage and open access for any client.
 *
 * \param[in]  partition       The subject storage_partition
 * \param[in]  partition_guid  The unique partition GUID
 * \param[in]  num_blocks      The number of contiguous blocks
 * \param[in]  block_size      Block size in bytes
 */
void storage_partition_init(
	struct storage_partition *partition,
	const struct uuid_octets *partition_guid,
	size_t num_blocks,
	size_t block_size);

/**
 * \brief Cleans up a previously initialized storage_partition
 *
 * Should be called when the storage_partition is no longer needed.
 *
 * \param[in]  partition       The subject storage_partition
 */
void storage_partition_deinit(
	struct storage_partition *partition);

/**
 * \brief Grant access to a specific client
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  client_id    The client ID to grant access to
 * \return True if successful
 */
bool storage_partition_grant_access(
	struct storage_partition *partition,
	uint32_t client_id);

/**
 * \brief Assign ownership using a resolvable owner ID string
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  owner_id     Owner ID string
 * \return True if successful
 */
bool storage_partition_assign_ownership(
	struct storage_partition *partition,
	const char *owner_id);

/**
 * \brief Check if unique partition GUID matches
 *
 * \param[in]  partition       The subject storage_partition
 * \param[in]  partition_guid  The unique partition GUID
 * \return     True if GUID matches the storage partition GUID
 */
bool storage_partition_is_guid_matched(
	const struct storage_partition *partition,
	const struct uuid_octets *partition_guid);

/**
 * \brief Perform checks on opening a partition
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  client_id    The requesting client ID
 * \param[in]  authorizer	Optional authorizer function
 * \return     True if access permitted
 */
bool storage_partition_is_open_permitted(
	struct storage_partition *partition,
	uint32_t client_id,
	storage_partition_authorizer authorizer);

/**
 * \brief Check if access to the storage partition is permitted
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  client_id    The requesting client ID
 * \return     True if access permitted
 */
bool storage_partition_is_access_permitted(
	const struct storage_partition *partition,
	uint32_t client_id);

/**
 * \brief Check if lba is legal for partition
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  lba          The LBA to check
 * \return     True if legal
 */
bool storage_partition_is_lba_legal(
	const struct storage_partition *partition,
	uint64_t lba);

/**
 * \brief Clip the length if it exceeds the limits of the partition
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  lba          The start LBA
 * \param[in]  offset       Byte off set from start of block
 * \param[in]  req_len      Requested length
 * \return     Clipped length if req_len exceeds limit of partition
 */
size_t storage_partition_clip_length(
	const struct storage_partition *partition,
	uint64_t lba,
	size_t offset,
	size_t req_len);

/**
 * \brief Clip the number of blocks if it exceeds the limits of the partition
 *
 * \param[in]  partition    The subject storage_partition
 * \param[in]  lba          The start LBA
 * \param[in]  num_blocks   Requested num_blocks
 * \return     Clipped num_blocks if request number exceeds the limits of the partition
 */
size_t storage_partition_clip_num_blocks(
	const struct storage_partition *partition,
	uint64_t lba,
	size_t num_blocks);

#ifdef __cplusplus
}
#endif

#endif /* STORAGE_PARTITION_H */
