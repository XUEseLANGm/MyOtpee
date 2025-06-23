/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PB_HELPER_H
#define PB_HELPER_H

#include <pb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PB_PACKET_LENGTH(payload_length)	((payload_length) + 16)

/* Returns an initialised pb_callback_t structure for encoding a variable length byte array */
extern pb_callback_t pb_out_byte_array(const pb_bytes_array_t *byte_array);

/* Returns an initialised pb_callback_t structure for decoding a variable length byte array */
extern pb_callback_t pb_in_byte_array(pb_bytes_array_t *byte_array);

/* Malloc space for a pb_bytes_array_t object with space for the requested number of bytes */
extern pb_bytes_array_t *pb_malloc_byte_array(size_t num_bytes);

/* Malloc space for a pb_bytes_array_t object containing the given string */
extern pb_bytes_array_t *pb_malloc_byte_array_containing_string(const char *str);

/* Malloc space for a pb_bytes_array_t object containing the given bytes */
extern pb_bytes_array_t *pb_malloc_byte_array_containing_bytes(const uint8_t *buf, size_t num_bytes);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PB_HELPER_H */
