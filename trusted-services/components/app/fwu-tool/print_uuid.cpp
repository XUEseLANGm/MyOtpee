/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "print_uuid.h"

#include "common/uuid/uuid.h"

std::string print_uuid(const uint8_t *uuid_octets)
{
	struct uuid_canonical canonical_uuid;

	uuid_canonical_from_guid_octets(&canonical_uuid, (const struct uuid_octets *)uuid_octets);

	return std::string(canonical_uuid.characters);
}
