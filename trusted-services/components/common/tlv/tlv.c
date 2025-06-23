/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tlv.h"
#include <string.h>

size_t tlv_required_space(size_t length)
{
    return TLV_HDR_LEN + length;
}

void tlv_iterator_begin(struct tlv_iterator *iter, uint8_t *buf, size_t bufsize)
{
    iter->pos = buf;
    iter->limit = &buf[bufsize];

    /* Defend against overflow */
    if (iter->limit < buf) iter->limit = buf;

    /* Used to enforce ascending tag order when encoding */
    iter->prev_tag = 0;
}

void tlv_const_iterator_begin(struct tlv_const_iterator *iter, const uint8_t *buf, size_t bufsize)
{
    iter->pos = buf;
    iter->limit = &buf[bufsize];

    /* Defend against overflow */
    if (iter->limit < buf) iter->limit = buf;
}

bool tlv_encode(struct tlv_iterator *iter, const struct tlv_record *input)
{
    bool success = false;
    size_t required_space = tlv_required_space(input->length);
    size_t available_space = iter->limit - iter->pos;

    if (required_space <= available_space && input->tag >= iter->prev_tag) {

        iter->pos[TLV_TAG_OFFSET + 0] = (uint8_t)(input->tag >> 8);
        iter->pos[TLV_TAG_OFFSET + 1] = (uint8_t)(input->tag);
        iter->pos[TLV_LENGTH_OFFSET + 0] = (uint8_t)(input->length >> 8);
        iter->pos[TLV_LENGTH_OFFSET + 1] = (uint8_t)(input->length);

        memcpy(&iter->pos[TLV_VALUE_OFFSET], input->value, input->length);

        iter->pos += required_space;
        iter->prev_tag = input->tag;
        success = true;
    }

    return success;
}

bool tlv_decode(struct tlv_const_iterator *iter, struct tlv_record *output)
{
    bool success = false;
    size_t max_space = iter->limit - iter->pos;

    if (max_space >= TLV_HDR_LEN) {

        size_t record_len;
        output->tag = (iter->pos[TLV_TAG_OFFSET + 0] << 8) | iter->pos[TLV_TAG_OFFSET + 1];
        output->length = (iter->pos[TLV_LENGTH_OFFSET + 0] << 8) | iter->pos[TLV_LENGTH_OFFSET + 1];
        output->value = &iter->pos[TLV_VALUE_OFFSET];

        record_len = output->length + TLV_HDR_LEN;

        if (record_len <= max_space) {

            iter->pos += record_len;
            success = true;
        }
    }

    return success;
}

bool tlv_find_decode(struct tlv_const_iterator *iter, uint16_t tag, struct tlv_record *output)
{
    struct tlv_const_iterator temp_iter = *iter;

    while (tlv_decode(&temp_iter, output)) {

        if (output->tag == tag) {
            /* Found a record - update input iterator to next record */
            *iter = temp_iter;
            return true;
        }
        else if (output->tag > tag) {
            /* Iterated beyond the expected parameter */
            return false;
        }
    }

    /* Reached the end of the buffer without finding a record with the requested tag */
    return false;
}
