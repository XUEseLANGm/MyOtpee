/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FVB_BLOCK_STORE_H
#define FVB_BLOCK_STORE_H

#include <stdint.h>
#include "service/block_storage/block_store/device/block_device.h"
#include "FirmwareVolumeBlock.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief fvb_block_store structure
 *
 * A fvb_block_store is a block_device that uses an instance of an EFI FVB driver
 * to access storage. Acts as an adapter to allow for reuse of drivers from external
 * projects such as edk2-platforms.
 */
struct fvb_block_store
{
	struct block_device base_block_device;
	EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *fvb_instance;
};

/**
 * \brief Initialize a fvb_block_store
 *
 * \param[in]  fvb_block_store  The subject fvb_block_store
 * \param[in]  fvb_instance     The fvb instance
  *
 * \return Pointer to block_store or NULL on failure
 */
struct block_store *fvb_block_store_init(
	struct fvb_block_store *fvb_block_store,
	EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *fvb_instance);

/**
 * \brief De-initialize a fvb_block_store
 *
 * \param[in]  fvb_block_store  The subject fvb_block_store
 */
void fvb_block_store_deinit(
	struct fvb_block_store *fvb_block_store);

#ifdef __cplusplus
}
#endif

#endif /* FVB_BLOCK_STORE_H */
