/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BLOCK_STORE_H
#define BLOCK_STORE_H

#include <stddef.h>
#include <stdint.h>
#include "psa/error.h"
#include "common/uuid/uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Opaque storage partition handle
 *
 * An opaque handle to a storage partition opened with a block_store. The meaning of
 * the handle is private to the concrete block_store that issued the handle.
 */
typedef uint32_t storage_partition_handle_t;

/**
 * \brief Information about a storage partition
 *
 * A structure that holds information about the storage partition identified
 * by the specified unique partition GUID.
 */
struct storage_partition_info
{
	/* Number of contiguous blocks from LBA zero */
	size_t num_blocks;

	/* Block size in bytes */
	size_t block_size;

	/* The unique partition GUID */
	struct uuid_octets partition_guid;

	/* GUID of the parent partition/device e.g. the disk GUID of the disk that
	 * contains the subject storage partition. A nil UUID should be returned if
	 * there is no parent.
	 */
	struct uuid_octets parent_guid;
};

/**
 * \brief Base block_store interface
 *
 * The block_store_interface structure provides a common interface for
 * accessing a block-level storage device. A concrete block_store provides
 * an implementation of this interface. A block_store provides access to
 * one or more storage partitions, each identified by a unique GUID.
 */
struct block_store_interface
{
	/**
	 * \brief Get information about a partition
	 *
	 * \param[in]  context         The concrete block_store context
	 * \param[in]  partition_guid  Identifies the storage partition
	 * \param[out] info            The partition info structure
	 *
	 * \return A status indicating whether the operation succeeded or not.
	 *
	 * \retval PSA_SUCCESS                     Operation completed successfully
	 * \retval PSA_ERROR_INVALID_ARGUMENT      Unrecognized partition GUID
	 */
	psa_status_t (*get_partition_info)(void *context,
		const struct uuid_octets *partition_guid,
		struct storage_partition_info *info);

	/**
	 * \brief Open a storage partition identified by its unique partition GUID.
	 *
	 * \param[in]  context         The concrete block_store context
	 * \param[in]  client_id       The requesting client ID
	 * \param[in]  partition_guid  Identifies the storage partition
	 * \param[out] handle          The handle to use during the open partition
	 *
	 * \return A status indicating whether the operation succeeded or not.
	 *
	 * \retval PSA_SUCCESS                     Operation completed successfully
	 * \retval PSA_ERROR_NOT_PERMITTED         Access not permitted
	 * \retval PSA_ERROR_INVALID_ARGUMENT      At least one parameter is invalid
	 */
	psa_status_t (*open)(void *context,
		uint32_t client_id,
		const struct uuid_octets *partition_guid,
		storage_partition_handle_t *handle);

	/**
	 * \brief Close a previously opened storage partition.
	 *
	 * \param[in]  context         The concrete block_store context
	 * \param[in]  client_id       The requesting client ID
	 * \param[in]  handle          The handle corresponding to the partition to close
	 *
	 * \return A status indicating whether the operation succeeded or not.
	 *
	 * \retval PSA_SUCCESS                     Operation completed successfully
	 * \retval PSA_ERROR_INVALID_ARGUMENT      Invalid handle
	 */
	psa_status_t (*close)(void *context,
		uint32_t client_id,
		storage_partition_handle_t handle);

	/**
	 * \brief Read a block
	 *
	 * The function must not read following blocks even if the buffer_size suggests it.
	 *
	 * \param[in]  context         The concrete block_store context
	 * \param[in]  client_id       The requesting client ID
	 * \param[in]  handle          The handle corresponding to the open storage partition
	 * \param[in]  lba             The logical block address
	 * \param[in]  offset          Offset into the block at which to begin reading
	 * \param[in]  buffer_size     The size of the client provided buffer
	 * \param[in]  buffer          The buffer to land read data into
	 * \param[out] data_len        The number of bytes read.
	 *
	 * \return A status indicating whether the operation succeeded or not.
	 *
	 * \retval PSA_SUCCESS                     Operation completed successfully
	 * \retval PSA_ERROR_INVALID_ARGUMENT      Invalid parameter e.g. LBA is invalid
	 * \retval PSA_ERROR_BUFFER_TOO_SMALL      Buffer not big enough
	 */
	psa_status_t (*read)(void *context,
		uint32_t client_id,
		storage_partition_handle_t handle,
		uint64_t lba,
		size_t offset,
		size_t buffer_size,
		uint8_t *buffer,
		size_t *data_len);

	/**
	 * \brief Write a block
	 *
	 * The function must not write following blocks even if the data_len suggests it.
	 *
	 * \param[in]  context         The concrete block_store context
	 * \param[in]  client_id       The requesting client ID
	 * \param[in]  handle          The handle corresponding to the open storage partition
	 * \param[in]  lba             The logical block address
	 * \param[in]  offset          Offset into the block at which to begin writing
	 * \param[in]  data            The data to write
	 * \param[in]  data_len        The number of bytes to write.
	 * \param[out] num_written     The number of bytes written.
	 *
	 * \return A status indicating whether the operation succeeded or not.
	 *
	 * \retval PSA_SUCCESS                     Operation completed successfully
	 * \retval PSA_ERROR_INVALID_ARGUMENT      Invalid parameter e.g. LBA is invalid
	 */
	psa_status_t (*write)(void *context,
		uint32_t client_id,
		storage_partition_handle_t handle,
		uint64_t lba,
		size_t offset,
		const uint8_t *data,
		size_t data_len,
		size_t *num_written);

	/**
	 * \brief Erase a set of contiguous blocks
	 *
	 * Erase the specified set of  contiguous blocks. If a storage technology does not explicitly
	 * support erase but instead, performs erase on write, a concrete block_store should silently
	 * do nothing on erase and always return PSA_SUCCESS. If an end_lba is specified that is
	 * beyond the last block in the partition, the range of erased blocks will be clipped to
	 * the end of the partition.
	 *
	 * \param[in]  context       The concrete block_store context
	 * \param[in]  client_id     The requesting client ID
	 * \param[in]  handle        The handle corresponding to the open storage partition
	 * \param[in]  begin_lba     LBA of first block to erase
	 * \param[in]  num_blocks    Number of contiguous blocks to erase
	 *
	 * \return A status indicating whether the operation succeeded or not.
	 *
	 * \retval PSA_SUCCESS                     Operation completed successfully
	 * \retval PSA_ERROR_INVALID_ARGUMENT      Invalid parameter e.g. LBA is invalid
	 */
	psa_status_t (*erase)(void *context,
		uint32_t client_id,
		storage_partition_handle_t handle,
		uint64_t begin_lba,
		size_t num_blocks);
};

/**
 * \brief Base block_store structure
 *
 * A concrete block store is responsible for initializing this structure to
 * enable the block store to be accessed via the generic block_store_interface
 * function pointers.
 */
struct block_store
{
	/**
	 * \brief The opaque context
	 *
	 * This is a pointer to the instance data of a block_store specialization that
	 * realizes the block_store interface. The concrete type of the pointer is specific
	 * to the specialization.
	 */
	void *context;

	/**
	 * \brief Pointer to a concrete block_store_interface
	 */
	const struct block_store_interface *interface;
};

/**
 * \brief Public interface functions for calling concrete block_store functions
 *
 */
psa_status_t block_store_get_partition_info(struct block_store *block_store,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info);

psa_status_t block_store_open(struct block_store *block_store,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle);

psa_status_t block_store_close(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle);

psa_status_t block_store_read(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	size_t buffer_size,
	uint8_t *buffer,
	size_t *data_len);

psa_status_t block_store_write(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	const uint8_t *data,
	size_t data_len,
	size_t *num_written);

psa_status_t block_store_erase(struct block_store *block_store,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t begin_lba,
	size_t num_blocks);

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_STORE_H */
