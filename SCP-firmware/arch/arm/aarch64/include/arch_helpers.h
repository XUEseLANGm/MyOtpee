/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARCH_HELPERS_H
#define ARCH_HELPERS_H

#include <fwk_status.h>

#include <arch_reg.h>

/*!
 * \brief Enables global CPU interrupts.
 *
 * \note inline is necessary as this call can be used in performance sensitive
 *     path
 */
inline static void arch_interrupts_enable(unsigned int not_used)
{
    __asm__ volatile("msr DAIFClr, %0" ::"i"(DAIF_FIQ) : "memory");
}

/*!
 * \brief Disables global CPU interrupts.

 * \note inline is necessary as this call can be used in performance sensitive
 *     path
 */
inline static unsigned int arch_interrupts_disable()
{
    __asm__ volatile("msr DAIFSet, %0" ::"i"(DAIF_FIQ) : "memory");

    return 0;
}

/*!
 * \brief Suspend execution of current CPU.

 * \note CPU will be woken up by receiving interrupts.
 *
 */
inline static void arch_suspend(void)
{
    __asm volatile("wfe");
}

#endif /* ARCH_HELPERS_H */
