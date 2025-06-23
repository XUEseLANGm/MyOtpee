/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMON_UUID_H
#define COMMON_UUID_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define UUID_OCTETS_LEN                 (16)
#define UUID_CANONICAL_FORM_LEN         (36)


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Structure for holding an octet representation of a UUID.
 *
 * There are two common byte orderings for octet representations of UUIDs.
 * RFC4122 specifies that integer fields from the UUID data structure
 * should be presented with most significant bytes first. An alternative
 * byte ordering, used by UEFI, presents integer values with the reverse
 * byte order (little Endian). The UEFI specification uses the GUID rather
 * than UUID acronym. To distinguish between the two octet representations,
 * functions that assume the little Endian octet encoding include 'guid' in
 * the function name.
 */
struct uuid_octets
{
	uint8_t octets[UUID_OCTETS_LEN];
};

/*
 * Structure for holding an canonical string representation of a UUID.
 */
struct uuid_canonical
{
	char characters[UUID_CANONICAL_FORM_LEN + 1];
};

/*
 * Check if uuid string in canonical form is valid. Returns the number of
 * valid characters. This will either be UUID_CANONICAL_FORM_LEN or zero
 * if the string is invalid in some way.
 */
size_t uuid_is_valid(const char *canonical_form);

/*
 * Check if two octet uuid representations are equal
 */
bool uuid_is_equal(const uint8_t *octets_a, const uint8_t *octets_b);

/*
 * Check if octets represent a nil uuid
 */
bool uuid_is_nil(const uint8_t *octets);

/*
 * Return a const nil uuid
 */
const struct uuid_octets *uuid_get_nil(void);

/*
 * Parses a uuid string in canonical string form, outputting as an array of bytes
 * in the standard big endian byte order. Returns the number of characters parsed
 * from the input string. Returns zero if there is a parsing error.
 */
size_t uuid_parse_to_octets(const char *canonical_form,
	uint8_t *buf, size_t buf_size);

/*
 * Parses a uuid string in canonical string form, outputting as an array of bytes
 * in little endian byte order (GUID order).
 */
size_t uuid_parse_to_guid_octets(const char *canonical_form,
	uint8_t *buf, size_t buf_size);

/*
 * Convert from one octet representation to the other. Works both ways.
 */
void uuid_reverse_octets(const struct uuid_octets *input_octets,
	uint8_t *buf, size_t buf_size);

/*
 * Converts a valid canonical uuid string to the standard octet byte order. Should only
 * be used if the input canonical string is trusted to be valid. Will assert if it's not.
 */
void uuid_octets_from_canonical(struct uuid_octets *uuid_octets,
	const char *canonical_form);

/*
 * Converts a valid canonical uuid string to the GUID octet byte order. Should only
 * be used if the input canonical string is trusted to be valid. Will assert if it's not.
 */
void uuid_guid_octets_from_canonical(struct uuid_octets *uuid_octets,
	const char *canonical_form);

/*
 * Converts an octet representation in standard byte order to a canonical string.
 */
void uuid_canonical_from_octets(struct uuid_canonical *canonical_form,
	const struct uuid_octets *uuid_octets);

/*
 * Converts an octet representation in GUID byte order to a canonical string.
 */
void uuid_canonical_from_guid_octets(struct uuid_canonical *canonical_form,
	const struct uuid_octets *uuid_octets);


#ifdef __cplusplus
}
#endif

#endif /* COMMON_UUID_H */
