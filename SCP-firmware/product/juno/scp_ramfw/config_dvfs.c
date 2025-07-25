/*
 * Arm SCP/MCP Software
 * Copyright (c) 2020-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config_dvfs.h"
#include "config_psu.h"
#include "juno_alarm_idx.h"
#include "juno_clock.h"
#include "juno_id.h"

#include <mod_dvfs.h>
#include <mod_scmi_perf.h>

#include <fwk_assert.h>
#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_macros.h>
#include <fwk_module.h>
#include <fwk_module_idx.h>
#include <fwk_status.h>

#include <stddef.h>

/*
 * The power cost figures from this file are built using the dynamic power
 * consumption formula (P = CfV^2), where C represents the capacitance of one
 * processing element in the domain (a core or shader core). This power figure
 * is scaled linearly with the number of processing elements in the performance
 * domain to give a rough representation of the overall power draw. The
 * capacitance constants are given in mW/MHz/V^2 and were taken from the Linux
 * device trees, which provide a dynamic-power-coefficient field in uW/MHz/V^2.
 */

static const struct mod_dvfs_domain_config cpu_group_little_r0 = {
    .psu_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VLITTLE),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_LITTLECLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_VLITTLE_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 2,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 450 * 1000000UL,
                .frequency = 450 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(0.14 * 450 * 0.820 * 0.820),
            },
            {
                .level = 575 * 1000000UL,
                .frequency = 575 * FWK_KHZ,
                .voltage = 850,
                .power = (uint32_t)(0.14 * 575 * 0.850 * 0.850),
            },
            {
                .level = 700 * 1000000UL,
                .frequency = 700 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(0.14 * 700 * 0.900 * 0.900),
            },
            {
                .level = 775 * 1000000UL,
                .frequency = 775 * FWK_KHZ,
                .voltage = 950,
                .power = (uint32_t)(0.14 * 775 * 0.950 * 0.950),
            },
            {
                .level = 850 * 1000000UL,
                .frequency = 850 * FWK_KHZ,
                .voltage = 1000,
                .power = (uint32_t)(0.14 * 850 * 1.000 * 1.000),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config cpu_group_little_r1 = {
    .psu_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VLITTLE),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_LITTLECLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_VLITTLE_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 0,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 650 * 1000000UL,
                .frequency = 650 * FWK_KHZ,
                .voltage = 800,
                .power = (uint32_t)(0.14 * 650 * 0.800 * 0.800),
            },
            { 0 },
        }
};

static const struct mod_dvfs_domain_config cpu_group_little_r2 = {
    .psu_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VLITTLE),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_LITTLECLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_VLITTLE_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 1,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 450 * 1000000UL,
                .frequency = 450 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(0.14 * 450 * 0.820 * 0.820),
            },
            {
                .level = 800 * 1000000UL,
                .frequency = 800 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(0.14 * 800 * 0.900 * 0.900),
            },
            {
                .level = 950 * 1000000UL,
                .frequency = 950 * FWK_KHZ,
                .voltage = 1000,
                .power = (uint32_t)(0.14 * 950 * 1.000 * 1.000),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config cpu_group_big_r0 = {
    .psu_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VBIG),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_BIGCLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_BIG_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 2,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 450 * 1000000UL,
                .frequency = 450 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(0.53 * 450 * 0.820 * 0.820),
            },
            {
                .level = 625 * 1000000UL,
                .frequency = 625 * FWK_KHZ,
                .voltage = 850,
                .power = (uint32_t)(0.53 * 625 * 0.850 * 0.850),
            },
            {
                .level = 800 * 1000000UL,
                .frequency = 800 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(0.53 * 800 * 0.900 * 0.900),
            },
            {
                .level = 950 * 1000000UL,
                .frequency = 950 * FWK_KHZ,
                .voltage = 950,
                .power = (uint32_t)(0.53 * 950 * 0.950 * 0.950),
            },
            {
                .level = 1100 * 1000000UL,
                .frequency = 1100 * FWK_KHZ,
                .voltage = 1000,
                .power = (uint32_t)(0.53 * 1100 * 1.000 * 1.000),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config cpu_group_big_r1 = {
    .psu_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VBIG),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_BIGCLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_BIG_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 1,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 600 * 1000000UL,
                .frequency = 600 * FWK_KHZ,
                .voltage = 800,
                .power = (uint32_t)(0.53 * 600 * 0.800 * 0.800),
            },
            {
                .level = 900 * 1000000UL,
                .frequency = 900 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(0.53 * 900 * 0.900 * 0.900),
            },
            {
                .level = 1150 * 1000000UL,
                .frequency = 1150 * FWK_KHZ,
                .voltage = 1000,
                .power = (uint32_t)(0.53 * 1150 * 1.000 * 1.000),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config cpu_group_big_r2 = {
    .psu_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VBIG),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_BIGCLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_BIG_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 1,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 600 * 1000000UL,
                .frequency = 600 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(0.45 * 600 * 0.820 * 0.820),
            },
            {
                .level = 1000 * 1000000UL,
                .frequency = 1000 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(0.45 * 1000 * 0.900 * 0.900),
            },
            {
                .level = 1200 * 1000000UL,
                .frequency = 1200 * FWK_KHZ,
                .voltage = 1000,
                .power = (uint32_t)(0.45 * 1200 * 1.000 * 1.000),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config gpu_r0 = {
    .psu_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VGPU),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_GPUCLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_GPU_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 4,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 450 * 1000000UL,
                .frequency = 450 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(4.6875 * 450 * 0.820 * 0.820),
            },
            {
                .level = 487500 * 1000UL,
                .frequency = 487500,
                .voltage = 825,
                .power = (uint32_t)(4.6875 * 487.5 * 0.825 * 0.825),
            },
            {
                .level = 525 * 1000000UL,
                .frequency = 525 * FWK_KHZ,
                .voltage = 850,
                .power = (uint32_t)(4.6875 * 525 * 0.850 * 0.850),
            },
            {
                .level = 562500 * 1000UL,
                .frequency = 562500,
                .voltage = 875,
                .power = (uint32_t)(4.6875 * 562.5 * 0.875 * 0.875),
            },
            {
                .level = 600 * 1000000UL,
                .frequency = 600 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(4.6875 * 600 * 0.900 * 0.900),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config gpu_r1 = {
    .psu_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VGPU),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_GPUCLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_GPU_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 4,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 450 * 1000000UL,
                .frequency = 450 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(4.6875 * 450 * 0.820 * 0.820),
            },
            {
                .level = 487500 * 1000UL,
                .frequency = 487500,
                .voltage = 825,
                .power = (uint32_t)(4.6875 * 487.5 * 0.825 * 0.825),
            },
            {
                .level = 525 * 1000000UL,
                .frequency = 525 * FWK_KHZ,
                .voltage = 850,
                .power = (uint32_t)(4.6875 * 525 * 0.850 * 0.850),
            },
            {
                .level = 562500 * 1000UL,
                .frequency = 562500,
                .voltage = 875,
                .power = (uint32_t)(4.6875 * 562.5 * 0.875 * 0.875),
            },
            {
                .level = 600 * 1000000UL,
                .frequency = 600 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(4.6875 * 600 * 0.900 * 0.900),
            },
            { 0 } }
};

static const struct mod_dvfs_domain_config gpu_r2 = {
    .psu_id = FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_PSU, MOD_PSU_ELEMENT_IDX_VGPU),
    .clock_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_CLOCK, JUNO_CLOCK_IDX_GPUCLK),
    .alarm_id = FWK_ID_SUB_ELEMENT_INIT(
        FWK_MODULE_IDX_TIMER,
        0,
        JUNO_DVFS_ALARM_GPU_IDX),
    .retry_us = 1000,
    .latency = 1450,
    .sustained_idx = 1,
    .opps =
        (struct mod_dvfs_opp[]){
            {
                .level = 450 * 1000000UL,
                .frequency = 450 * FWK_KHZ,
                .voltage = 820,
                .power = (uint32_t)(4.6875 * 450 * 0.820 * 0.820),
            },
            {
                .level = 600 * 1000000UL,
                .frequency = 600 * FWK_KHZ,
                .voltage = 900,
                .power = (uint32_t)(4.6875 * 600 * 0.900 * 0.900),
            },
            { 0 } }
};

static const struct fwk_element element_table_r0[] = {
    [DVFS_ELEMENT_IDX_LITTLE] = {
        .name = "LITTLE_CPU",
        .data = &cpu_group_little_r0,
    },
    [DVFS_ELEMENT_IDX_BIG] = {
        .name = "BIG_CPU",
        .data = &cpu_group_big_r0,
    },
    [DVFS_ELEMENT_IDX_GPU] = {
        .name = "GPU",
        .data = &gpu_r0,
    },
    { 0 }
};

static const struct fwk_element element_table_r1[] = {
    [DVFS_ELEMENT_IDX_LITTLE] = {
        .name = "LITTLE_CPU",
        .data = &cpu_group_little_r1,
    },
    [DVFS_ELEMENT_IDX_BIG] = {
        .name = "BIG_CPU",
        .data = &cpu_group_big_r1,
    },
    [DVFS_ELEMENT_IDX_GPU] = {
        .name = "GPU",
        .data = &gpu_r1,
    },
    { 0 }
};

static const struct fwk_element element_table_r2[] = {
    [DVFS_ELEMENT_IDX_LITTLE] = {
        .name = "LITTLE_CPU",
        .data = &cpu_group_little_r2,
    },
    [DVFS_ELEMENT_IDX_BIG] = {
        .name = "BIG_CPU",
        .data = &cpu_group_big_r2,
    },
    [DVFS_ELEMENT_IDX_GPU] = {
        .name = "GPU",
        .data = &gpu_r2,
    },
    { 0 }
};

static const struct fwk_element *dvfs_get_element_table(fwk_id_t module_id)
{
    int status;
    enum juno_idx_revision revision = (enum juno_idx_revision)0U;

    status = juno_id_get_revision(&revision);
    fwk_assert(status == FWK_SUCCESS);

    if (revision == JUNO_IDX_REVISION_R0) {
        return element_table_r0;
    }
    if (revision == JUNO_IDX_REVISION_R1) {
        return element_table_r1;
    }
    return element_table_r2;
}

struct fwk_module_config config_dvfs = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(dvfs_get_element_table),
};
