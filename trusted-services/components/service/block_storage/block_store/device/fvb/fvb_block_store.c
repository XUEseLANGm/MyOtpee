/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include <trace.h>
#include "fvb_block_store.h"


static psa_status_t fvb_block_store_get_partition_info(void *context,
	const struct uuid_octets *partition_guid,
	struct storage_partition_info *info)
{
	struct fvb_block_store *this_instance = (struct fvb_block_store *)context;

	return block_device_get_partition_info(&this_instance->base_block_device,
		partition_guid, info);
}

static psa_status_t fvb_block_store_open(void *context,
	uint32_t client_id,
	const struct uuid_octets *partition_guid,
	storage_partition_handle_t *handle)
{
	struct fvb_block_store *this_instance = (struct fvb_block_store *)context;
	psa_status_t status = PSA_ERROR_BAD_STATE;

	if (this_instance->fvb_instance) {

		status = block_device_open(&this_instance->base_block_device,
			client_id, partition_guid, handle);
	}

	return status;
}

static psa_status_t fvb_block_store_close(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle)
{
	struct fvb_block_store *this_instance = (struct fvb_block_store *)context;

	return block_device_close(&this_instance->base_block_device, client_id, handle);
}

static psa_status_t fvb_block_store_read(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	size_t buffer_size,
	uint8_t *buffer,
	size_t *data_len)
{
	struct fvb_block_store *this_instance =(struct fvb_block_store *)context;
	psa_status_t status = block_device_check_access_permitted(
		&this_instance->base_block_device, client_id, handle);

	*data_len = 0;

	if (status == PSA_SUCCESS) {

		const struct storage_partition *storage_partition =
			&this_instance->base_block_device.storage_partition;

		if (storage_partition_is_lba_legal(storage_partition, lba) &&
			(offset < storage_partition->block_size)) {

			EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *fvb = this_instance->fvb_instance;

			if (!fvb)
				return PSA_ERROR_BAD_STATE;

			unsigned int num_bytes = buffer_size;
			EFI_STATUS efi_status = fvb->Read(fvb, lba, offset, &num_bytes, buffer);

			if (efi_status == EFI_SUCCESS) {

				*data_len = num_bytes;
			} else {

				EMSG("FVB Read failed: %ld", efi_status);
				status = PSA_ERROR_GENERIC_ERROR;
			}
		}
		else {

			/* Block or offset outside of configured limits */
			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

static psa_status_t fvb_block_store_write(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t lba,
	size_t offset,
	const uint8_t *data,
	size_t data_len,
	size_t *num_written)
{
	struct fvb_block_store *this_instance = (struct fvb_block_store*)context;
	psa_status_t status = block_device_check_access_permitted(
		&this_instance->base_block_device, client_id, handle);

	*num_written = 0;

	if (status == PSA_SUCCESS) {

		const struct storage_partition *storage_partition =
			&this_instance->base_block_device.storage_partition;

		if (storage_partition_is_lba_legal(storage_partition, lba) &&
			(offset < storage_partition->block_size)) {

			EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *fvb = this_instance->fvb_instance;

			if (!fvb)
				return PSA_ERROR_BAD_STATE;

			unsigned int num_bytes = data_len;
			EFI_STATUS efi_status = fvb->Write(fvb, lba, offset, &num_bytes, (UINT8 *)data);

			if (efi_status == EFI_SUCCESS) {

				*num_written = num_bytes;
			} else {

				EMSG("FVB Write failed: %ld", efi_status);
				status = PSA_ERROR_GENERIC_ERROR;
			}
		}
		else {

			/* Block or offset outside of configured limits */
			status = PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return status;
}

static psa_status_t fvb_block_store_erase(void *context,
	uint32_t client_id,
	storage_partition_handle_t handle,
	uint64_t begin_lba,
	size_t num_blocks)
{
	struct fvb_block_store *this_instance = (struct fvb_block_store*)context;
	const struct storage_partition *storage_partition =
		&this_instance->base_block_device.storage_partition;

	psa_status_t status = block_device_check_access_permitted(
		&this_instance->base_block_device, client_id, handle);

	/* Sanitize the range of LBAs to erase */
	if ((status == PSA_SUCCESS) &&
		!storage_partition_is_lba_legal(storage_partition, begin_lba)) {

		status = PSA_ERROR_INVALID_ARGUMENT;
	}

	if (status == PSA_SUCCESS) {

		EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *fvb = this_instance->fvb_instance;

		if (!fvb)
			return PSA_ERROR_BAD_STATE;

		EFI_STATUS efi_status = fvb->EraseBlocks(fvb,
			begin_lba, num_blocks, EFI_LBA_LIST_TERMINATOR);

		if (efi_status != EFI_SUCCESS) {

			EMSG("FVB Erase failed: %ld", efi_status);
			status = PSA_ERROR_GENERIC_ERROR;
		}
	}

	return status;
}

struct block_store *fvb_block_store_init(
	struct fvb_block_store *this_instance,
	EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL *fvb_instance)
{
	assert(this_instance);
	assert(fvb_instance);

	struct block_store *block_store = NULL;

	this_instance->fvb_instance = fvb_instance;

	/* Define concrete block store interface */
	static const struct block_store_interface interface =
	{
		fvb_block_store_get_partition_info,
		fvb_block_store_open,
		fvb_block_store_close,
		fvb_block_store_read,
		fvb_block_store_write,
		fvb_block_store_erase
	};

	/* Initialize base block_store */
	this_instance->base_block_device.base_block_store.context = this_instance;
	this_instance->base_block_device.base_block_store.interface = &interface;

	/* Retrieve size information from the FVB driver */
	unsigned int num_blocks = 0;
	unsigned int block_size = 0;

	EFI_STATUS efi_status = fvb_instance->GetBlockSize(fvb_instance,
		0, &block_size, &num_blocks);

	if (efi_status == EFI_SUCCESS) {

		block_store = block_device_init(&this_instance->base_block_device,
			NULL, num_blocks, block_size);
	} else {

		this_instance->fvb_instance = NULL;
		EMSG("FVB GetBlockSize failed: %ld", efi_status);
	}

	return block_store;
}

void fvb_block_store_deinit(
	struct fvb_block_store *this_instance)
{
	this_instance->fvb_instance = NULL;

	block_device_deinit(&this_instance->base_block_device);
}
