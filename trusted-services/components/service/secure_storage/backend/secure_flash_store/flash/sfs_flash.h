/*
 * Copyright (c) 2017-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __SFS_FLASH_H__
#define __SFS_FLASH_H__

#include <stddef.h>
#include <stdint.h>

#include <protocols/service/psa/packed-c/status.h>
#include "../sfs_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Adjust to match the size of the flash device's physical program unit */
#define SFS_FLASH_PROGRAM_UNIT (0x1)

/* Invalid block index */
#define SFS_BLOCK_INVALID_ID 0xFFFFFFFFU

/* FIXME: Duplicated from flash info */
#if (SFS_FLASH_PROGRAM_UNIT <= 16)
#define SFS_FLASH_ALIGNMENT SFS_FLASH_PROGRAM_UNIT
#else
#define SFS_FLASH_ALIGNMENT 1
#endif

/**
 * \brief Provides a compile-time constant for the maximum program unit required
 *        by any flash device that can be accessed through this interface.
 */
#define SFS_FLASH_MAX_ALIGNMENT SFS_UTILS_MAX(SFS_FLASH_ALIGNMENT, \
                                              1)

/**
 * \struct sfs_flash_info_t
 *
 * \brief Structure containing the required information about a flash device to
 *        be used by the SFS Flash FS.
 */
struct sfs_flash_info_t {
    /**
     * \brief Initialize the Flash Interface.
     *
     * \param[in] info  Flash device information
     *
     * \return Returns PSA_SUCCESS if the function is executed correctly.
     *         Otherwise, it returns PSA_ERROR_STORAGE_FAILURE.
     */
    psa_status_t (*init)(const struct sfs_flash_info_t *info);

    /**
     * \brief Reads block data from the position specified by block ID and
     *        offset.
     *
     * \param[in]  info      Flash device information
     * \param[in]  block_id  Block ID
     * \param[out] buff      Buffer pointer to store the data read
     * \param[in]  offset    Offset position from the init of the block
     * \param[in]  size      Number of bytes to read
     *
     * \note This function assumes all input values are valid. That is, the
     *       address range, based on block_id, offset and size, is a valid range
     *       in flash.
     *
     * \return Returns PSA_SUCCESS if the function is executed correctly.
     *         Otherwise, it returns PSA_ERROR_STORAGE_FAILURE.
     */
    psa_status_t (*read)(const struct sfs_flash_info_t *info, uint32_t block_id,
                         uint8_t *buff, size_t offset, size_t size);

    /**
     * \brief Writes block data to the position specified by block ID and
     *        offset.
     *
     * \param[in] info      Flash device information
     * \param[in] block_id  Block ID
     * \param[in] buff      Buffer pointer to the write data
     * \param[in] offset    Offset position from the init of the block
     * \param[in] size      Number of bytes to write
     *
     * \note This function assumes all input values are valid. That is, the
     *       address range, based on block_id, offset and size, is a valid range
     *       in flash.
     *
     * \return Returns PSA_SUCCESS if the function is executed correctly.
     *         Otherwise, it returns PSA_ERROR_STORAGE_FAILURE.
     */
    psa_status_t (*write)(const struct sfs_flash_info_t *info,
                          uint32_t block_id, const uint8_t *buff, size_t offset,
                          size_t size);

    /**
     * \brief Flushes modifications to a block to flash. Must be called after a
     *        sequence of calls to write() (including via
     *        sfs_flash_block_to_block_move()) for one block ID, before any call
     *        to the same functions for a different block ID.
     *
     * \param[in] info  Flash device information
     *
     * \note It is permitted for write() to commit block updates immediately, in
     *       which case this function is a no-op.
     *
     * \return Returns PSA_SUCCESS if the function is executed correctly.
     *         Otherwise, it returns PSA_ERROR_STORAGE_FAILURE.
     */
    psa_status_t (*flush)(const struct sfs_flash_info_t *info);

    /**
     * \brief Erases block ID data.
     *
     * \param[in] info      Flash device information
     * \param[in] block_id  Block ID
     *
     * \note This function assumes the input value is valid.
     *
     * \return Returns PSA_SUCCESS if the function is executed correctly.
     *         Otherwise, it returns PSA_ERROR_STORAGE_FAILURE.
     */
    psa_status_t (*erase)(const struct sfs_flash_info_t *info,
                          uint32_t block_id);

    void *flash_dev;          /**< Pointer to the flash device */
    uint32_t flash_area_addr; /**< Start address of the flash area */
    uint16_t sector_size;     /**< Size of the flash device's physical erase
                               *   unit
                               */
    uint16_t block_size;      /**< Size of a logical erase unit presented by the
                               *   flash interface, a multiple of sector_size.
                               */
    uint16_t num_blocks;      /**< Number of logical erase blocks */
    uint16_t program_unit;    /**< Minimum size of a program operation */
    uint16_t max_file_size;   /**< Maximum file size */
    uint16_t max_num_files;   /**< Maximum number of files */
    uint8_t erase_val;        /**< Value of a byte after erase (usually 0xFF) */
};

/**
 * \brief Moves data from source block ID to destination block ID.
 *
 * \param[in] info        Flash device information
 * \param[in] dst_block   Destination block ID
 * \param[in] dst_offset  Destination offset position from the init of the
 *                        destination block
 * \param[in] src_block   Source block ID
 * \param[in] src_offset  Source offset position from the init of the source
 *                        block
 * \param[in] size        Number of bytes to moves
 *
 * \note This function assumes all input values are valid. That is, the address
 *       range, based on blockid, offset and size, is a valid range in flash.
 *       It also assumes that the destination block is already erased and ready
 *       to be written.
 *
 * \return Returns PSA_SUCCESS if the function is executed correctly. Otherwise,
 *         it returns PSA_ERROR_STORAGE_FAILURE.
 */
psa_status_t sfs_flash_block_to_block_move(const struct sfs_flash_info_t *info,
                                           uint32_t dst_block,
                                           size_t dst_offset,
                                           uint32_t src_block,
                                           size_t src_offset,
                                           size_t size);

#ifdef __cplusplus
}
#endif

#endif /* __SFS_FLASH_H__ */
