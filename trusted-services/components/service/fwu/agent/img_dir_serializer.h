/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef IMG_DIR_SERIALIZER_H
#define IMG_DIR_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct fw_directory;
struct fw_store;

/**
 * \brief Serialize the public image directory
 *
 *  Using content from the internal fw_directory and fw_store, create
 *  a serialized image_directory that conforms to the FWU-A specification
 *  format.
 *
 * \param[in]  fw_dir         Source fw_directory
 * \param[in]  fw_store       Source fw_store
 * \param[in]  buf            Serialize into this buffer
 * \param[in]  buf_size       Size of buffer
 * \param[out] data_len       Length of serialized data
 *
 * \return Status
 */
int img_dir_serializer_serialize(const struct fw_directory *fw_dir, const struct fw_store *fw_store,
				 uint8_t *buf, size_t buf_size, size_t *data_len);

/**
 * \brief Return the length in bytes of the serialized image directory
 *
 * \param[in]  fw_dir         Source fw_directory
 *
 * \return Size in bytes
 */
size_t img_dir_serializer_get_len(const struct fw_directory *fw_dir);

#ifdef __cplusplus
}
#endif

#endif /* IMG_DIR_SERIALIZER_H */
