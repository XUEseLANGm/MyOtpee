/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPC_UUID_H
#define RPC_UUID_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief RPC UUID
 *
 * Describes a UUID for identifying an RPC service.
 */
struct rpc_uuid {
	uint8_t uuid[16];
};

/**
 * @brief Checks if two RPC UUIDs are equal
 *
 * @param uuid_a UUID A
 * @param uuid_b UUID B
 * @return true
 * @return false
 */
bool rpc_uuid_equal(const struct rpc_uuid *uuid_a, const struct rpc_uuid *uuid_b);

#ifdef __cplusplus
}
#endif

#endif /* RPC_UUID_H */
