/*
 * Arm SCP/MCP Software
 * Copyright (c) 2023-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "clock_soc.h"
#include "scp_mmap.h"

#include <mod_gtimer.h>
#include <mod_timer.h>

#include <fwk_id.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <fwk_time.h>

/*
 * Generic timer driver config
 */
static const struct fwk_element gtimer_dev_table[2] = {
    [0] = { .name = "GTCLK",
            .data = &((struct mod_gtimer_dev_config){
                .hw_timer = SCP_GTCLK_CNTBASE0_BASE,
                .hw_counter = SCP_GTCLK_CNTCTL_BASE,
                .control = SCP_GTCLK_CNTCONTROL_BASE,
                .frequency = CLOCK_RATE_GTCLK,
                .clock_id = FWK_ID_ELEMENT_INIT(
                   FWK_MODULE_IDX_CLOCK,
                   CLOCK_IDX_CPU_GROUP_LITTLE),
        }),
    },
    [1] = { 0 },
};

const struct fwk_module_config config_gtimer = {
    .elements = FWK_MODULE_STATIC_ELEMENTS_PTR(gtimer_dev_table),
};

struct fwk_time_driver fmw_time_driver(const void **ctx)
{
    return mod_gtimer_driver(ctx, config_gtimer.elements.table[0].data);
}
