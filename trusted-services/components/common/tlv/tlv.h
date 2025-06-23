/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TLV_H
#define TLV_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TLV provides a general purpose serialization for variable length
 * objects, identified by a tag.  A serialized TLV record has the following
 * structure:
 *      |   Tag     |  Length   |       Value       |
 *      | (16-bits) | (16-bits) |   (Length bytes)  |
 *
 * No assumptions are made about the alignment of the start of a serialized record.
 * Tag and Length fields are encoded in Big Endian byte order.
 */
#define TLV_TAG_WIDTH			        (2)
#define TLV_LENGTH_WIDTH			    (2)
#define TLV_HDR_LEN			            (TLV_TAG_WIDTH + TLV_LENGTH_WIDTH)
#define TLV_TAG_OFFSET			        (0)
#define TLV_LENGTH_OFFSET			    TLV_TAG_WIDTH
#define TLV_VALUE_OFFSET			    TLV_HDR_LEN

/*
 * TLV record structure provides access to a serialized record.
 */
struct tlv_record
{
    uint16_t tag;
    uint16_t length;
    const uint8_t *value;
};

/*
 * Iterator state for interating over serialized tlv records when encoding.
 */
struct tlv_iterator
{
    uint8_t *pos;
    uint8_t *limit;
    uint16_t prev_tag;
};

/*
 * Iterator state for interating over serialized tlv records when decoding.
 */
struct tlv_const_iterator
{
    const uint8_t *pos;
    const uint8_t *limit;
};

/*
 *  Return the space required in bytes for a serialized record with the
 *  specified value length.
 */
size_t tlv_required_space(size_t length);

/*
 * Initializes a TLV iterator to the start of a buffer.  Used when writing
 * records to a buffer when encoding.
 */
void tlv_iterator_begin(struct tlv_iterator *iter, uint8_t *buf, size_t bufsize);

/*
 * Initializes a TLV const iterator to the start of a buffer.  Used when reading
 * records from a buffer when decoding.
 */
void tlv_const_iterator_begin(struct tlv_const_iterator *iter, const uint8_t *buf, size_t bufsize);

/*
 * Encode a serialized record and advance the iterator, ready to encode the next
 * record.  Returns true if successful, false if insufficient room.
 */
bool tlv_encode(struct tlv_iterator *iter, const struct tlv_record *input);

/*
 * Decode a serialized record and advance the iterator, ready to decode the next
 * record (if there is one).  Returns true if successful, false there is no serialized record
 * or an incomplete one.
 */
bool tlv_decode(struct tlv_const_iterator *iter, struct tlv_record *output);

/*
 * Advances the iterator until a record with the specified tag is found.  If
 * it's found, it's decoded and the iterator is advanced to the next position.
 * This can be used when decoding an expected set of records, encoded in ascending
 * tag order.  Any unrecognised records are skipped over.  This is the typical
 * decoding pattern.
 */
bool tlv_find_decode(struct tlv_const_iterator *iter, uint16_t tag, struct tlv_record *output);

#ifdef __cplusplus
}
#endif

#endif /* TLV_H */
