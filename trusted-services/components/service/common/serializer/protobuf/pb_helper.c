/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include "pb_helper.h"
#include <pb_encode.h>
#include <pb_decode.h>

static bool pb_encode_byte_array(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {

    const pb_bytes_array_t *byte_array = (const pb_bytes_array_t *)*arg;
    if (!pb_encode_tag_for_field(stream, field)) return false;

    return pb_encode_string(stream, byte_array->bytes, byte_array->size);
}

static bool pb_decode_byte_array(pb_istream_t *stream, const pb_field_t *field, void **arg) {

    (void)field;
    pb_bytes_array_t *byte_array = (pb_bytes_array_t *)*arg;
    if (stream->bytes_left > byte_array->size) return false;

    byte_array->size = stream->bytes_left;

    return pb_read(stream, byte_array->bytes, stream->bytes_left);
}

pb_callback_t pb_out_byte_array(const pb_bytes_array_t *byte_array) {

    pb_callback_t callback;
    callback.funcs.encode = pb_encode_byte_array;
    callback.arg = (void*)byte_array;

    return callback;
}

pb_callback_t pb_in_byte_array(pb_bytes_array_t *byte_array) {

    pb_callback_t callback;
    callback.funcs.decode = pb_decode_byte_array;
    callback.arg = (void*)byte_array;
    return callback;
}

pb_bytes_array_t *pb_malloc_byte_array(size_t num_bytes) {

    pb_bytes_array_t *byte_array = (pb_bytes_array_t*)malloc(offsetof(pb_bytes_array_t, bytes) + num_bytes);

    if (byte_array) {

        byte_array->size = num_bytes;
    }

    return byte_array;
}

pb_bytes_array_t *pb_malloc_byte_array_containing_string(const char *str) {

    pb_bytes_array_t *byte_array;
    size_t required_space = strlen(str) + 1;

    byte_array = pb_malloc_byte_array(required_space);

    if (byte_array) {

        memcpy(byte_array->bytes, str, required_space);
    }

    return byte_array;
}

pb_bytes_array_t *pb_malloc_byte_array_containing_bytes(const uint8_t *buf, size_t num_bytes) {

    pb_bytes_array_t *byte_array = pb_malloc_byte_array(num_bytes);

    if (byte_array) {

        memcpy(byte_array->bytes, buf, num_bytes);
    }

    return byte_array;
}
