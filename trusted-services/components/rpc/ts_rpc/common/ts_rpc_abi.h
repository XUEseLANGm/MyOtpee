/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_RPC_ABI_H
#define TS_RPC_ABI_H

#include "rpc_uuid.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Trusted-services RPC ABI function
 *
 * This file contains getters and setters for TS ABI fields. They handle the five arg registers of
 * the FF-A direct messages and extract or insert fields of suitable types.
 */

#define TS_RPC_ABI_FLAG_FAST_CALL			(0x01)

#define TS_RPC_ABI_MANAGEMENT_OPCODE_VERSION		(0)
#define TS_RPC_ABI_MANAGEMENT_OPCODE_MEMORY_RETRIEVE	(1)
#define TS_RPC_ABI_MANAGEMENT_OPCODE_MEMORY_RELINQUISH	(2)
#define TS_RPC_ABI_MANAGEMENT_OPCODE_INTERFACE_ID_QUERY	(3)

#define TS_RPC_ABI_VERSION_V1				(1)

uint8_t ts_rpc_abi_get_flags(const uint32_t regs[5]);
void ts_rpc_abi_set_flags(uint32_t regs[5], uint8_t flags);

uint8_t ts_rpc_abi_get_interface_id(const uint32_t regs[5]);
void ts_rpc_abi_set_interface_id(uint32_t regs[5], uint8_t interface_id);

bool ts_rpc_abi_is_management_interface_id(const uint32_t regs[5]);
void ts_rpc_abi_set_management_interface_id(uint32_t regs[5]);

uint16_t ts_rpc_abi_get_opcode(const uint32_t regs[5]);
void ts_rpc_abi_set_opcode(uint32_t regs[5], uint16_t interface_id);

void ts_rpc_abi_copy_control_reg(uint32_t response_regs[5], const uint32_t request_regs[5]);

uint32_t ts_rpc_abi_get_version(const uint32_t regs[5]);
void ts_rpc_abi_set_version(uint32_t regs[5], uint32_t version);

uint64_t ts_rpc_abi_get_memory_handle(const uint32_t regs[5]);
void ts_rpc_abi_set_memory_handle(uint32_t regs[5], uint64_t handle);

uint64_t ts_rpc_abi_get_memory_tag(const uint32_t regs[5]);
void ts_rpc_abi_set_memory_tag(uint32_t regs[5], uint64_t tag);

uint32_t ts_rpc_abi_get_rpc_status(const uint32_t regs[5]);
void ts_rpc_abi_set_rpc_status(uint32_t regs[5], uint32_t status);

uint32_t ts_rpc_abi_get_service_status(const uint32_t regs[5]);
void ts_rpc_abi_set_service_status(uint32_t regs[5], uint32_t status);

void ts_rpc_abi_get_uuid(const uint32_t regs[5], struct rpc_uuid *uuid);
void ts_rpc_abi_set_uuid(uint32_t regs[5], const struct rpc_uuid *uuid);

uint8_t ts_rpc_abi_get_queried_interface_id(const uint32_t regs[5]);
void ts_rpc_abi_set_queried_interface_id(uint32_t regs[5], uint8_t interface_id);

uint32_t ts_rpc_abi_get_request_length(const uint32_t regs[5]);
void ts_rpc_abi_set_request_length(uint32_t regs[5], uint32_t length);

uint32_t ts_rpc_abi_get_client_id(const uint32_t regs[5]);
void ts_rpc_abi_set_client_id(uint32_t regs[5], uint32_t client_id);

uint32_t ts_rpc_abi_get_response_length(const uint32_t regs[5]);
void ts_rpc_abi_set_response_length(uint32_t regs[5], uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* TS_RPC_ABI_H */
