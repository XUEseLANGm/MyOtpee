/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CBOR_DUMP_H
#define CBOR_DUMP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dictionary entry for mapping a CBOR ID to a string.
 */
struct cbor_dictionary_entry
{
    int32_t     id;
    const char  *string;
};

/**
 * Dump decoded cbor to the specified file.
 *
 * \param[in] file          Dump to this file
 * \param[in] cbor          Serialized cbor to decode
 * \param[in] cbor_len      Length of the cbor
 * \param[in] indent        Initial indentation of dump output
 * \param[in] root_label    Root label or NULL if none.
 * \param[in] dictionary    Dictionary of IDs to strings.  NULL if none.
 * \param[in] dictionary_len Number of entries in the dictionary.
 */
int cbor_dump(FILE *file,
    const uint8_t *cbor, size_t cbor_len,
    unsigned int indent, const char *root_label,
    const struct cbor_dictionary_entry *dictionary, unsigned int dictionary_len);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CBOR_DUMP_H */
