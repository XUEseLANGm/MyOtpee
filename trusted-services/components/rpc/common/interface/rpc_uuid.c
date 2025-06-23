/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpc_uuid.h"
#include <string.h>

bool rpc_uuid_equal(const struct rpc_uuid *uuid_a, const struct rpc_uuid *uuid_b)
{
	return memcmp(uuid_a->uuid, uuid_b->uuid, sizeof(uuid_a->uuid)) == 0;
}
