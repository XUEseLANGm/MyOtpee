/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FWU_STREAM_MANAGER_H
#define FWU_STREAM_MANAGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Manages the set of streams used by the update_agent for image installation
 * and accessing other FWU related objects. A subject of stream objects is managed
 * to allow for concurrent streams if needed. To defend against a badly behaved
 * client that fails to close streams, if necessary, the least recently used
 * open stream will be reused if necessary to prevent a denial of service attack
 * where a rogue client opens streams but doesn't close them.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct fw_store;
struct installer;
struct image_info;

/**
 *  The default stream subject size
 */
#ifndef FWU_STREAM_MANAGER_POOL_SIZE
#define FWU_STREAM_MANAGER_POOL_SIZE (4)
#endif

/**
 *  Identifier for the type of stream
 */
enum fwu_stream_type { FWU_STREAM_TYPE_NONE, FWU_STREAM_TYPE_BUFFER, FWU_STREAM_TYPE_INSTALL };

/**
 * A stream context
 */
struct stream_context {
	enum fwu_stream_type type;
	uint32_t handle;
	struct stream_context *next;
	struct stream_context *prev;

	union stream_variant {
		/* Buffer stream variant */
		struct buffer_variant {
			size_t pos;
			const uint8_t *data;
			size_t data_len;

		} buffer;

		/* Install stream variant */
		struct install_variant {
			struct fw_store *fw_store;
			struct installer *installer;
			const struct image_info *image_info;

		} install;

	} variant;
};

/**
 * The stream_manager structure.
 */
struct stream_manager {
	struct stream_context contexts[FWU_STREAM_MANAGER_POOL_SIZE];
	struct stream_context *free;
	struct stream_context *active_head;
	struct stream_context *active_tail;
	uint16_t rolling_count;
};

/**
 * \brief One-time initialization
 *
 * \param[in]  subject    The subject stream_manager
 */
void stream_manager_init(struct stream_manager *subject);

/**
 * \brief De-initializes a stream_manager
 *
 * \param[in]  subject    The subject stream_manager
 */
void stream_manager_deinit(struct stream_manager *subject);

/**
 * \brief Open a buffer stream
 *
 * Opens a stream for reading from a buffer containing the complete object
 * to access.
 *
 * \param[in]  subject    The subject stream_manager
 * \param[in]  data       Pointer to the buffer containing data
 * \param[in]  data_len   The length of the data
 * \param[out] stream_handle   The stream handle to use for subsequent operations
 *
 * \return FWU status
 */
int stream_manager_open_buffer_stream(struct stream_manager *subject, const uint8_t *data,
				      size_t data_len, uint32_t *stream_handle);

/**
 * \brief Open an install stream
 *
 * Open a stream for writing an image to an installer. A concrete installer
 * is responsible for installing the image into storage.
 *
 * \param[in]  subject       The subject stream_manager
 * \param[in]  fw_store      The image_info for the image to install
 * \param[in]  installer     The installer
 * \param[in]  image_info    The image_info corresponding to the image to install
 * \param[out] stream_handle The stream_handle to use for subsequent operations
 *
 * \return FWU status
 */
int stream_manager_open_install_stream(struct stream_manager *subject, struct fw_store *fw_store,
				       struct installer *installer,
				       const struct image_info *image_info,
				       uint32_t *stream_handle);

/**
 * \brief Close a previously opened stream
 *
 * \param[in]  subject    The subject stream_manager
 * \param[in]  stream_handle   Stream handle
 * \param[in]  accepted   The initial accepted state for an installed image
 *
 * \return FWU status
 */
int stream_manager_close(struct stream_manager *subject, uint32_t stream_handle, bool accepted);

/**
 * \brief Cancel all streams of the specified type
 *
 * \param[in]  subject    The subject stream_manager
 * \param[in]  type       Type of stream to cancel
 */
void stream_manager_cancel_streams(struct stream_manager *subject, enum fwu_stream_type type);

/**
 * \brief Check for any open streams of the specified type
 *
 * \param[in]  subject    The subject stream_manager
 * \param[in]  type       Type of stream to check
 *
 * \return True is any are open
 */
bool stream_manager_is_open_streams(const struct stream_manager *subject,
				    enum fwu_stream_type type);

/**
 * \brief Write to a previously opened stream
 *
 * \param[in]  subject    The subject stream_manager
 * \param[in]  stream_handle  The handle returned by open
 * \param[in]  data       Pointer to data
 * \param[in]  data_len   The data length
 *
 * \return Status (0 on success)
 */
int stream_manager_write(struct stream_manager *subject, uint32_t stream_handle,
			 const uint8_t *data, size_t data_len);

/**
 * \brief Read from a previously opened stream
 *
 * \param[in]  subject    The subject stream_manager
 * \param[in]  stream_handle The handle returned by open
 * \param[in]  buf        Pointer to buffer to copy to
 * \param[in]  buf_size   The size of the buffer
 * \param[out] read_len   The length of data read
 * \param[out] total_len  The total length of object to read
 *
 * \return Status (0 on success)
 */
int stream_manager_read(struct stream_manager *subject, uint32_t handle, uint8_t *buf,
			size_t buf_size, size_t *read_len, size_t *total_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FWU_STREAM_MANAGER_H */
