/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BLOCK_STORAGE_PROVIDER_SERIALIZER_H
#define BLOCK_STORAGE_PROVIDER_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include "common/uuid/uuid.h"
#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include "service/block_storage/block_store/block_store.h"

/* Provides a common interface for parameter serialization operations
 * for the block storage service provider.  Allows alternative serialization
 * protocols to be used without hard-wiring a particular protocol
 * into the service provider code.  A concrete serializer must
 * implement this interface.
 */
struct block_storage_serializer {

	/* Operation: get_partition_info */
	rpc_status_t (*deserialize_get_partition_info_req)(const struct rpc_buffer *req_buf,
		struct uuid_octets *partition_guid);

	rpc_status_t (*serialize_get_partition_info_resp)(struct rpc_buffer *resp_buf,
		struct storage_partition_info *info);

	/* Operation: open */
	rpc_status_t (*deserialize_open_req)(const struct rpc_buffer *req_buf,
		struct uuid_octets *partition_guid);

	rpc_status_t (*serialize_open_resp)(struct rpc_buffer *resp_buf,
		storage_partition_handle_t handle);

	/* Operation: close */
	rpc_status_t (*deserialize_close_req)(const struct rpc_buffer *req_buf,
		storage_partition_handle_t *handle);

	/* Operation: read */
	rpc_status_t (*deserialize_read_req)(const struct rpc_buffer *req_buf,
		storage_partition_handle_t *handle,
		uint64_t *lba,
		size_t *offset,
		size_t *len);

	/* Operation: write */
	rpc_status_t (*deserialize_write_req)(const struct rpc_buffer *req_buf,
		storage_partition_handle_t *handle,
		uint64_t *lba,
		size_t *offset,
		const uint8_t **data,
		size_t *data_len);

	rpc_status_t (*serialize_write_resp)(struct rpc_buffer *resp_buf,
		size_t num_written);

	/* Operation: erase */
	rpc_status_t (*deserialize_erase_req)(const struct rpc_buffer *req_buf,
		storage_partition_handle_t *handle,
		uint64_t *begin_lba,
		size_t *num_blocks);
};

#endif /* BLOCK_STORAGE_PROVIDER_SERIALIZER_H */
