/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FVP_BASER_AEMV8R_MMAP_H
#define FVP_BASER_AEMV8R_MMAP_H

#include <fwk_macros.h>

#define FVP_DRAM_BASE    0x00000000
#define FVP_ITC_RAM_SIZE (256 * 1024)
#define FVP_DTC_RAM_SIZE (256 * 1024)
#define FVP_ITC_RAM_BASE FVP_DRAM_BASE
#define FVP_DTC_RAM_BASE (FVP_DRAM_BASE + FVP_ITC_RAM_SIZE)

#define FVP_PERIPHERAL_BASE 0x80000000
#define FVP_GICD_BASE       (FVP_PERIPHERAL_BASE + 0x2F000000)
#define FVP_GICR_BASE       (FVP_PERIPHERAL_BASE + 0x2F100000)
#define FVP_GIC_BASE        FVP_GICD_BASE
#define FVP_GIC_SIZE        (16 * FWK_MIB)
#define FVP_UART_BASE       (FVP_PERIPHERAL_BASE + 0x1C090000)
#define FVP_UART_SIZE       (64 * FWK_KIB)
#define FVP_WATCHDOG_BASE   (FVP_PERIPHERAL_BASE + 0x1C0F0000)
#define FVP_WATCHDOG_SIZE   (64 * FWK_KIB)

#endif /* FVP_BASER_AEMV8R_MMAP_H */
