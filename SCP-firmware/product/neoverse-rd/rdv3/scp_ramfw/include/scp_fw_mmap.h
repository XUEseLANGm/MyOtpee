/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Base address and size definitions for the various SCP's firmware defined
 *     memory carveouts.
 */

#ifndef SCP_FW_MMAP_H
#define SCP_FW_MMAP_H

#include "rsm_fw_mmap.h"
#include "scp_css_mmap.h"

#include <fwk_macros.h>

#include <stdint.h>

/*
 * AP Peripheral SRAM in the AP memory map with base address of 0x00000000 is
 * mapped in the SCP's address translation window 0 (0x60000000 - 0x9FFFFFFF)
 * at the offset 'SCP_ATW0_AP_PERIPHERAL_SRAM_OFFSET' via ATU configuration.
 */

/* Secure SRAM size reserved by AP */
#define SCP_AP_PERIPHERAL_SRAM_TRUSTED_RESERVED (0x19000)

/* AP Peripheral trusted SRAM base in SCP's memory map */
#define SCP_AP_PERIPHERAL_SRAM_TRUSTED_BASE \
    (SCP_ATW0_AP_PERIPHERAL_SRAM_BASE + SCP_AP_PERIPHERAL_SRAM_TRUSTED_RESERVED)
#define SCP_AP_PERIPHERAL_SRAM_TRUSTED_SIZE (4 * FWK_KIB)

/* AP Peripheral non-trusted SRAM base in SCP's memory map */
#define SCP_AP_PERIPHERAL_SRAM_NONTRUSTED_BASE \
    (SCP_ATW0_AP_PERIPHERAL_SRAM_BASE)
#define SCP_AP_PERIPHERAL_SRAM_NONTRUSTED_SIZE (4 * FWK_KIB)

/* Secure Shared memory between AP and SCP */
#define SCP_AP_PERIPHERAL_SRAM_SHARED_SECURE_BASE \
    (SCP_AP_PERIPHERAL_SRAM_TRUSTED_BASE)
#define SCP_AP_PERIPHERAL_SRAM_SHARED_SECURE_SIZE (4 * FWK_KIB)

/*
 * SDS Memory Region inside Secure AP Peripheral SRAM that is shared between
 * AP and SCP.
 */
#define SCP_SDS_SECURE_BASE (SCP_AP_PERIPHERAL_SRAM_SHARED_SECURE_BASE)
#define SCP_SDS_SECURE_SIZE (3520)

/*
 * AP Context Memory Region inside Secure AP Peripheral SRAM that is shared
 * between AP and SCP.
 */
#define SCP_AP_CONTEXT_BASE \
    (SCP_AP_PERIPHERAL_SRAM_SHARED_SECURE_BASE + \
     SCP_AP_PERIPHERAL_SRAM_SHARED_SECURE_SIZE - SCP_AP_CONTEXT_SIZE)
#define SCP_AP_CONTEXT_SIZE (64)

/* SCMI Secure Payload Area */
#define SCP_SCMI_PAYLOAD_S_A2P_BASE (SCP_SDS_SECURE_BASE + SCP_SDS_SECURE_SIZE)
#define SCP_SCMI_PAYLOAD_SIZE       (128)

/*
 * RSM SRAM in the AP memory map with base address of 0x2F000000 is mapped in
 * the SCP's address translation window 0 (0x60000000 - 0x9FFFFFFF) at the
 * offset 'SCP_ATW0_SHARED_SRAM_RSM_BASE' via ATU configuration.
 */

/* SCP-MCP SCMI message payload base address (in RSM SRAM) */
#define SCP_MCP_SCMI_MSG_PAYLOAD_BASE \
    (SCP_SHARED_SRAM_RSM_BASE + SCP_MCP_SCMI_MSG_PAYLOAD_OFFSET)

/* Payload Area for SCP-RSE outband message */
#define SCP_RSE_SCMI_MSG_PAYLOAD_BASE \
    (SCP_SHARED_SRAM_RSM_BASE + SCP_RSE_SCMI_MSG_PAYLOAD_OFFSET)

#endif /* SCP_FW_MMAP_H */
