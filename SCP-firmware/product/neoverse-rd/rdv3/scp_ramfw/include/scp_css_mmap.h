/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Base address definitions for the SCP's sub-system and access extending
 *     into the rest of the CSS.
 */

#ifndef SCP_CSS_MMAP_H
#define SCP_CSS_MMAP_H

#include "css_common.h"

/* Base address and size of SCP's ITCM */
#define SCP_ITC_RAM_BASE (0x00000000)
#define SCP_ITC_RAM_SIZE (256 * 1024)

/* Base address and size of SCP's DTCM */
#define SCP_DTC_RAM_BASE (0x20000000)
#define SCP_DTC_RAM_SIZE (256 * 1024)

/* SCP sub-system peripherals */
#define SCP_REFCLK_CNTCONTROL_BASE    (0x2A430000)
#define SCP_SID_BASE                  (0x2A4A0000)
#define SCP_REFCLK_CNTCTL_BASE        (0x44000000)
#define SCP_REFCLK_CNTBASE0_BASE      (0x44001000)
#define SCP_UART_BASE                 (0x44002000)
#define SCP_SCP2AP_MHUV3_SEND_S_BASE  (0x45020000)
#define SCP_AP2SCP_MHUV3_RCV_S_BASE   (0x45030000)
#define SCP_SCP2MCP_MHUV3_SEND_S_BASE (0x45800000)
#define SCP_MCP2SCP_MHUV3_RCV_S_BASE  (0x45810000)
#define SCP_SCP2RSS_MHUV3_SEND_S_BASE (0x46000000)
#define SCP_RSS2SCP_MHUV3_RCV_S_BASE  (0x46010000)
#define SCP_POWER_CONTROL_BASE        (0x50000000)
#define SCP_ATU_BASE                  (0x50010000)
#define SCP_SYSTEM_PIK_BASE           (0x50040000)
#define SCP_PPU_SYS0_BASE             (0x50041000)

/* Base address of SCP expansion memory regions */
#define SCP_SOC_EXPANSION3_BASE (0x40000000) /* 64MB size */

/* SCP addresses mapped via ATU into address translation windows */
#define SCP_ADDRESS_TRANSLATION_WINDOW0_BASE (0x60000000)
#define SCP_ADDRESS_TRANSLATION_WINDOW1_BASE (0xA0000000)

/*
 * Offsets within SCP's Address Translation Window0
 *          __________________________  0x78600000
 *         |                          |
 *         |     ATU MMIO (1M)        |
 *         |__________________________| 0x78500000
 *         |                          |
 *         |     RSM_SRAM (4MB)       |
 *         |__________________________| 0x78100000
 *         |                          |
 *         |     GPC_MMU (1MB)        |
 *         |__________________________| 0x78000000
 *         |                          |
 *         |     SHARED SRAM (128MB)  |
 *         |__________________________| 0x70000000
 *         |                          |
 *         |     CLUTER UTIL (256MB)  |
 *         |__________________________| 0x60000000
 */

#define SCP_ATW0_LCP_AND_CLUSTER_UTILITY_SIZE (256 * FWK_MIB)
#define SCP_ATW0_AP_PERIPHERAL_SRAM_SIZE      (128 * FWK_MIB)
#define SCP_ATW0_AP_PERIPHERAL_GPC_SMMU_SIZE  (1 * FWK_MIB)
#define SCP_ATW0_ATU_MMIO_SIZE                (1 * FWK_MIB)

#define SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE \
    SCP_ADDRESS_TRANSLATION_WINDOW0_BASE
#define SCP_ATW0_AP_PERIPHERAL_SRAM_BASE \
    (SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE + \
     SCP_ATW0_LCP_AND_CLUSTER_UTILITY_SIZE)
#define SCP_ATW0_AP_PERIPHERAL_GPC_SMMU_BASE \
    (SCP_ATW0_AP_PERIPHERAL_SRAM_BASE + SCP_ATW0_AP_PERIPHERAL_SRAM_SIZE)
#define SCP_ATW0_SHARED_SRAM_RSM_BASE \
    (SCP_ATW0_AP_PERIPHERAL_GPC_SMMU_BASE + \
     SCP_ATW0_AP_PERIPHERAL_GPC_SMMU_SIZE)
#define SCP_ATW0_ATU_MMIO_BASE \
    (SCP_ATW0_SHARED_SRAM_RSM_BASE + RSM_SHARED_SRAM_SIZE)

/*
 * Offsets within SCP's Address Translation Window1
 *          __________________________  0xE0000000
 *         |                          |
 *         |         CMN (1GB)        |
 *         |__________________________| 0xA0000000
 */
#define SCP_ATW1_CMN_BASE (SCP_ADDRESS_TRANSLATION_WINDOW1_BASE)
#define SCP_ATW1_CMN_SIZE (1 * FWK_GIB)

/*
 * LCP subsystem and Cluster Utility memory region that is addressable in the AP
 * memory map between 0x2_0000_0000 - 0x2_0FFF_FFFF is mapped in the SCP address
 * translation window 0 from 0x6000_0000 to 0x6FFF_FFFF via ATU configuration.
 */

/*
 * Size of SCP's view of per-cluster LCP subsystem and utility memory region.
 */
#define SCP_LCP_AND_CLUSTER_UTILITY_SIZE (0x200000)

/*
 * Offsets of various blocks within LCP subsystem and cluster utility that is
 * mapped into SCP's address translation window 0. These offsets are applicable
 * to each cluster in the system.
 */
#define SCP_LCP_CONTROL_OFFSET                  (0x21000)
#define SCP_LCP_EXTERNAL_CONTROL_OFFSET         (0x70000)
#define SCP_CLUSTER_UTILITY_CORE_MANAGER_OFFSET (0x80000)
#define SCP_CLUSTER_UTILITY_CLUSTER_PPU_OFFSET  (0x130000)
#define SCP_CLUSTER_UTILITY_CORE_PPU_OFFSET     (0x180000)

/* Core Manager base address for a cluster 'n' */
#define SCP_CLUSTER_UTILITY_CORE_MANAGER_BASE(n) \
    (SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE + \
     (n * SCP_LCP_AND_CLUSTER_UTILITY_SIZE) + \
     SCP_CLUSTER_UTILITY_CORE_MANAGER_OFFSET)

/* Cluster PPU base address */
#define SCP_CLUSTER_UTILITY_CLUSTER_PPU_BASE(n) \
    (SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE + \
     (n * SCP_LCP_AND_CLUSTER_UTILITY_SIZE) + \
     SCP_CLUSTER_UTILITY_CLUSTER_PPU_OFFSET)

/* Application core PPU base address */
#define SCP_CLUSTER_UTILITY_CORE_PPU_BASE(n) \
    (SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE + \
     (n * SCP_LCP_AND_CLUSTER_UTILITY_SIZE) + \
     SCP_CLUSTER_UTILITY_CORE_PPU_OFFSET)

/* Base address of SCP's view of LCP's External Control register block */
#define SCP_LCP_EXTERNAL_CONTROL(n) \
    (SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE + \
     (n * SCP_LCP_AND_CLUSTER_UTILITY_SIZE) + SCP_LCP_EXTERNAL_CONTROL_OFFSET)

/* Offsets in the LCP external control register block */
#define SCP_LCP_EXT_CONTROL_UART_CTRL_OFFSET 0x20

/*
 * Base address of the LCP UART control regiser in the LCP External Control
 * register block.
 */
#define LCP_UART_CONTROL(n) \
    (SCP_LCP_EXTERNAL_CONTROL(n) + SCP_LCP_EXT_CONTROL_UART_CTRL_OFFSET)

/* Base address of SCP's view of LCP's Control register block */
#define SCP_LCP_CONTROL(n) \
    (SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE + \
     (n * SCP_LCP_AND_CLUSTER_UTILITY_SIZE) + SCP_LCP_CONTROL_OFFSET)

/* Offsets in the LCP control register block */
#define SCP_LCP_CONTROL_CPU_WAIT_OFFSET 0x120

/*
 * Base address of the LCP CPU WAIT register in the system control regiser block
 * located in the LCP Control register block.
 */
#define LCP_SYS_CTRL_CPU_WAIT(n) \
    (SCP_LCP_CONTROL(n) + SCP_LCP_CONTROL_CPU_WAIT_OFFSET)

/*
 * Shared RSM SRAM (shared between RSS, MCP, SCP) is mapped by ATU in
 * the SCP address translation window 0.
 */
#define SCP_SHARED_SRAM_RSM_BASE (SCP_ATW0_SHARED_SRAM_RSM_BASE)

/* CMN config space is mapped in the SCP address translation window 1 */
#define SCP_CMN_BASE SCP_ATW1_CMN_BASE

#endif /* SCP_CSS_MMAP_H */
