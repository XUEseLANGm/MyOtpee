/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef PARTITIONED_BLOCK_STORE_H
#define PARTITIONED_BLOCK_STORE_H

#include <stdbool.h>
#include "service/block_storage/block_store/block_store.h"
#include "service/block_storage/block_store/storage_partition.h"
#include "service/block_storage/block_store/storage_partition_acl.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PARTITIONED_BLOCK_STORE_MAX_PARTITIONS
#define PARTITIONED_BLOCK_STORE_MAX_PARTITIONS		(8)
#endif

/* Forward declaration */
struct partitioned_block_store;

/**
 * \brief partition configuration listener
 *
 * A callback for implementing on-demand partition configuration for cases when
 * there is a request to open a partition but the requested partition has not
 * yet been configured. Attaching a partition configuration listener is optional.
 *
 * \param[in]  partitioned_block_store  The subject partitioned_block_store
 * \param[in]  partition_guid   The requested partition GUID
 * \param[in]  back_store_info  Information about the back store
 *
 * \return Return true if configuration successful
 */
typedef bool (*partition_config_listener)(
	struct partitioned_block_store *partitioned_block_store,
	const struct uuid_octets *partition_guid,
	const struct storage_partition_info *back_store_info);

/**
 * \brief partitioned_block_store structure
 *
 * A partitioned_block_store is a stackable block_store that enables an underlying
 * block store to be presented as a set of independent storage partitions, each identified
 * by its own GUID. Storage partition attributes will have been defined by platform
 * configuration data e.g. read from a GPT. The method for obtaining partition configuration
 * is outside of the scope of the partitioned_block_store.
 */
struct partitioned_block_store
{
	struct block_store base_block_store;
	uint32_t local_client_id;
	storage_partition_authorizer authorizer;
	partition_config_listener config_listener;
	size_t num_partitions;
	struct storage_partition storage_partition[PARTITIONED_BLOCK_STORE_MAX_PARTITIONS];
	storage_partition_handle_t back_store_handle;
	struct block_store *back_store;
	struct storage_partition_info back_store_info;
};

/**
 * \brief Initialize a partitioned_block_store
 *
 * After initialization, no storage partitions are defined. Partitions must be added,
 * one a time, by calling partitioned_block_store_add_partition.
 *
 * \param[in]  partitioned_block_store  The subject partitioned_block_store
 * \param[in]  local_client_id   Client ID corresponding to the current environment
 * \param[in]  back_store_guid   The partition GUID to use in the underlying back store
 * \param[in]  back_store        The associated back store
 * \param[in]  authorizer        Optional authorizer function for authorizing clients
 *
 * \return Pointer to block_store or NULL on failure
 */
struct block_store *partitioned_block_store_init(
	struct partitioned_block_store *partitioned_block_store,
	uint32_t local_client_id,
	const struct uuid_octets *back_store_guid,
	struct block_store *back_store,
	storage_partition_authorizer authorizer);

/**
 * \brief De-initialize a partitioned_block_store
 *
 *  Frees resource allocated during call to partitioned_block_store_init().
 *
 * \param[in]  partitioned_block_store  The subject partitioned_block_store
 */
void partitioned_block_store_deinit(
	struct partitioned_block_store *partitioned_block_store);

/**
 * \brief Attach a config listener
 *
 * Allows an on-demand partition configurator to receive a callback when an
 * attempt is made to open a partition that has not been configured.
 *
 * \param[in]  partitioned_block_store  The subject partitioned_block_store
 * \param[in]  config_listener   Optional on-demand configurator
 */
void partitioned_block_store_attach_config_listener(
	struct partitioned_block_store *partitioned_block_store,
	partition_config_listener config_listener);

/**
 * \brief Add a storage partition
 *
 *  Called for each partition defined in platform configuration. Parameters
 *  correspond to partition parameters defined in the UEFI specification for
 *  GUID Partition Tables (GPT).
 *
 * \param[in]  partitioned_block_store  The subject partitioned_block_store
 * \param[in]  partition_guid  The unique partition GUID
 * \param[in]  starting_lba    The back store lba that corresponds to the partition start
 * \param[in]  ending_lba      The back store lba that corresponds to the final block in the partition
 * \param[in]  attributes      Partition attributes bitmap
 * \param[in]  owner           Partition owner ID string
 *
 * \return True if successful
 */
bool partitioned_block_store_add_partition(
	struct partitioned_block_store *partitioned_block_store,
	const struct uuid_octets *partition_guid,
	uint64_t starting_lba,
	uint64_t ending_lba,
	uint64_t attributes,
	const char *owner);

/**
 * \brief Get information about back store
 *
 *  Returns information about the underlying block device that is being partitioned
 *
 * \param[in]  partitioned_block_store  The subject partitioned_block_store
 *
 * \return Pointer to storage_partition_info structure.
 */
const struct storage_partition_info *partitioned_block_store_get_back_store_info(
	const struct partitioned_block_store *partitioned_block_store);

#ifdef __cplusplus
}
#endif

#endif /* PARTITIONED_BLOCK_STORE_H */
