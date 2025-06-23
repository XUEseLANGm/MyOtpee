/*
 * Copyright (c) 2018-2022, Arm Limited. All rights reserved.
 * Copyright (c) 2020 Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "sfs_flash.h"

#ifndef SFS_MAX_BLOCK_DATA_COPY
#define SFS_MAX_BLOCK_DATA_COPY 256
#endif

psa_status_t sfs_flash_block_to_block_move(const struct sfs_flash_info_t *info,
                                           uint32_t dst_block,
                                           size_t dst_offset,
                                           uint32_t src_block,
                                           size_t src_offset,
                                           size_t size)
{
    psa_status_t status;
    size_t bytes_to_move;
    uint8_t dst_block_data_copy[SFS_MAX_BLOCK_DATA_COPY];

    while (size > 0) {
        /* Calculates the number of bytes to move */
        bytes_to_move = SFS_UTILS_MIN(size, SFS_MAX_BLOCK_DATA_COPY);

        /* Reads data from source block and store it in the in-memory copy of
         * destination content.
         */
        status = info->read(info, src_block, dst_block_data_copy, src_offset,
                            bytes_to_move);
        if (status != PSA_SUCCESS) {
            return status;
        }

        /* Writes in flash the in-memory block content after modification */
        status = info->write(info, dst_block, dst_block_data_copy, dst_offset,
                             bytes_to_move);
        if (status != PSA_SUCCESS) {
            return status;
        }

        /* Updates pointers to the source and destination flash regions */
        dst_offset += bytes_to_move;
        src_offset += bytes_to_move;

        /* Decrement remaining size to move */
        size -= bytes_to_move;
    }

    return PSA_SUCCESS;
}
