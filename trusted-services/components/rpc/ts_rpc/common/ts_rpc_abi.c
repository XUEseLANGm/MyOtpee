/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ts_rpc_abi.h"
#include <string.h>

#define TS_RPC_CONTROL_REG			(0)

#define TS_RPC_FLAGS_REG			(0)
#define TS_RPC_FLAGS_SHIFT			(24)
#define TS_RPC_FLAGS_MASK			(0x3f)

#define TS_RPC_INTERFACE_ID_REG			(0)
#define TS_RPC_INTERFACE_ID_SHIFT		(16)
#define TS_RPC_INTERFACE_ID_MASK		(0xff)

#define TS_RPC_MANAGEMENT_INTERFACE_ID		(0xff)

#define TS_RPC_OPCODE_REG			(0)
#define TS_RPC_OPCODE_SHIFT			(0)
#define TS_RPC_OPCODE_MASK			(0xffff)

#define TS_RPC_VERSION_REG			(1)
#define TS_RPC_MEMORY_HANDLE_LSW_REG		(1)
#define TS_RPC_MEMORY_HANDLE_MSW_REG		(2)
#define TS_RPC_MEMORY_TAG_LSW_REG		(3)
#define TS_RPC_MEMORY_TAG_MSW_REG		(4)
#define TS_RPC_RPC_STATUS_REG			(1)
#define TS_RPC_SERVICE_STATUS_REG		(2)
#define TS_RPC_UUID_START_REG			(1)

#define TS_RPC_QUERIED_INTERFACE_ID_REG		(2)
#define TS_RPC_QUERIED_INTERFACE_ID_SHIFT	(0)
#define TS_RPC_QUERIED_INTERFACE_ID_MASK	(0xff)

#define TS_RPC_REQUEST_LENGTH_REG		(3)
#define TS_RPC_CLIENT_ID_REG			(4)
#define TS_RPC_RESPONSE_LENGTH_REG		(3)
#define TS_RPC_FAST_REQUEST_DATA_START_REG	(1)
#define TS_RPC_FAST_RESPONSE_DATA_START_REG	(2)

static uint32_t get_field(const uint32_t regs[5], uint32_t reg, uint32_t shift, uint32_t mask)
{
	return (regs[reg] >> shift) & mask;
}

static void set_field(uint32_t regs[5], uint32_t reg, uint32_t shift, uint32_t mask,
		      uint32_t value)
{
	regs[reg] &= ~(mask << shift);
	regs[reg] |= (value & mask) << shift;
}

uint8_t ts_rpc_abi_get_flags(const uint32_t regs[5])
{
	return get_field(regs, TS_RPC_FLAGS_REG, TS_RPC_FLAGS_SHIFT, TS_RPC_FLAGS_MASK);
}

void ts_rpc_abi_set_flags(uint32_t regs[5], uint8_t flags)
{
	set_field(regs, TS_RPC_FLAGS_REG, TS_RPC_FLAGS_SHIFT, TS_RPC_FLAGS_MASK, flags);
}

uint8_t ts_rpc_abi_get_interface_id(const uint32_t regs[5])
{
	return get_field(regs, TS_RPC_INTERFACE_ID_REG, TS_RPC_INTERFACE_ID_SHIFT,
			 TS_RPC_INTERFACE_ID_MASK);
}

void ts_rpc_abi_set_interface_id(uint32_t regs[5], uint8_t interface_id)
{
	set_field(regs, TS_RPC_INTERFACE_ID_REG, TS_RPC_INTERFACE_ID_SHIFT,
		  TS_RPC_INTERFACE_ID_MASK, interface_id);
}

bool ts_rpc_abi_is_management_interface_id(const uint32_t regs[5])
{
	return ts_rpc_abi_get_interface_id(regs) == TS_RPC_MANAGEMENT_INTERFACE_ID;
}

void ts_rpc_abi_set_management_interface_id(uint32_t regs[5])
{
	ts_rpc_abi_set_interface_id(regs, TS_RPC_MANAGEMENT_INTERFACE_ID);
}

uint16_t ts_rpc_abi_get_opcode(const uint32_t regs[5])
{
	return get_field(regs, TS_RPC_OPCODE_REG, TS_RPC_OPCODE_SHIFT, TS_RPC_OPCODE_MASK);
}

void ts_rpc_abi_set_opcode(uint32_t regs[5], uint16_t opcode)
{
	set_field(regs, TS_RPC_OPCODE_REG, TS_RPC_OPCODE_SHIFT, TS_RPC_OPCODE_MASK, opcode);
}

void ts_rpc_abi_copy_control_reg(uint32_t response_regs[5], const uint32_t request_regs[5])
{
	response_regs[TS_RPC_CONTROL_REG] = request_regs[TS_RPC_CONTROL_REG];
}

uint32_t ts_rpc_abi_get_version(const uint32_t regs[5])
{
	return regs[TS_RPC_VERSION_REG];
}

void ts_rpc_abi_set_version(uint32_t regs[5], uint32_t version)
{
	regs[TS_RPC_VERSION_REG] = version;
}

uint64_t ts_rpc_abi_get_memory_handle(const uint32_t regs[5])
{
	return (uint64_t)regs[TS_RPC_MEMORY_HANDLE_MSW_REG] << 32 |
		regs[TS_RPC_MEMORY_HANDLE_LSW_REG];
}

void ts_rpc_abi_set_memory_handle(uint32_t regs[5], uint64_t handle)
{
	regs[TS_RPC_MEMORY_HANDLE_LSW_REG] = handle;
	regs[TS_RPC_MEMORY_HANDLE_MSW_REG] = handle >> 32;
}

uint64_t ts_rpc_abi_get_memory_tag(const uint32_t regs[5])
{
	return (uint64_t)regs[TS_RPC_MEMORY_TAG_MSW_REG] << 32 | regs[TS_RPC_MEMORY_TAG_LSW_REG];
}

void ts_rpc_abi_set_memory_tag(uint32_t regs[5], uint64_t tag)
{
	regs[TS_RPC_MEMORY_TAG_LSW_REG] = tag;
	regs[TS_RPC_MEMORY_TAG_MSW_REG] = tag >> 32;
}

uint32_t ts_rpc_abi_get_rpc_status(const uint32_t regs[5])
{
	return regs[TS_RPC_RPC_STATUS_REG];
}

void ts_rpc_abi_set_rpc_status(uint32_t regs[5], uint32_t status)
{
	regs[TS_RPC_RPC_STATUS_REG] = status;
}

uint32_t ts_rpc_abi_get_service_status(const uint32_t regs[5])
{
	return regs[TS_RPC_SERVICE_STATUS_REG];
}

void ts_rpc_abi_set_service_status(uint32_t regs[5], uint32_t status)
{
	regs[TS_RPC_SERVICE_STATUS_REG] = status;
}

void ts_rpc_abi_get_uuid(const uint32_t regs[5], struct rpc_uuid *uuid)
{
	memcpy(uuid, &regs[TS_RPC_UUID_START_REG], sizeof(*uuid));
}

void ts_rpc_abi_set_uuid(uint32_t regs[5], const struct rpc_uuid *uuid)
{
	memcpy(&regs[TS_RPC_UUID_START_REG], uuid, sizeof(*uuid));
}

uint8_t ts_rpc_abi_get_queried_interface_id(const uint32_t regs[5])
{
	return get_field(regs, TS_RPC_QUERIED_INTERFACE_ID_REG, TS_RPC_QUERIED_INTERFACE_ID_SHIFT,
			 TS_RPC_QUERIED_INTERFACE_ID_MASK);
}

void ts_rpc_abi_set_queried_interface_id(uint32_t regs[5], uint8_t interface_id)
{
	set_field(regs, TS_RPC_QUERIED_INTERFACE_ID_REG, TS_RPC_QUERIED_INTERFACE_ID_SHIFT,
		  TS_RPC_QUERIED_INTERFACE_ID_MASK, interface_id);
}

uint32_t ts_rpc_abi_get_request_length(const uint32_t regs[5])
{
	return regs[TS_RPC_REQUEST_LENGTH_REG];
}

void ts_rpc_abi_set_request_length(uint32_t regs[5], uint32_t length)
{
	regs[TS_RPC_REQUEST_LENGTH_REG] = length;
}

uint32_t ts_rpc_abi_get_client_id(const uint32_t regs[5])
{
	return regs[TS_RPC_CLIENT_ID_REG];
}

void ts_rpc_abi_set_client_id(uint32_t regs[5], uint32_t client_id)
{
	regs[TS_RPC_CLIENT_ID_REG] = client_id;
}

uint32_t ts_rpc_abi_get_response_length(const uint32_t regs[5])
{
	return regs[TS_RPC_RESPONSE_LENGTH_REG];
}

void ts_rpc_abi_set_response_length(uint32_t regs[5], uint32_t length)
{
	regs[TS_RPC_RESPONSE_LENGTH_REG] = length;
}
