/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_arch.h>
#include <fwk_assert.h>
#include <fwk_macros.h>
#include <fwk_status.h>

#include <arch_helpers.h>

extern int arch_gic_init(const struct fwk_arch_interrupt_driver **driver);

static const struct fwk_arch_init_driver arch_init_driver = {
    .interrupt = arch_gic_init,
};

int arm_main(void)
{
    return fwk_arch_init(&arch_init_driver);
}
