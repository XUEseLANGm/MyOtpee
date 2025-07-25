/*
 * Arm SCP/MCP Software
 * Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Configuration data for module 'atu'.
 */

#include "platform_core.h"
#include "scp_css_mmap.h"

#include <mod_atu.h>

#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_log.h>
#include <fwk_macros.h>
#include <fwk_module.h>

/* Indices for ATU module elements */
enum cfgd_mod_atu_element_idx {
    CFGD_MOD_ATU_EIDX_ATU0,
    CFGD_MOD_ATU_EIDX_COUNT
};

#define MOD_ATU_ELEMENT_COUNT (CFGD_MOD_ATU_EIDX_COUNT + 1)

/* Indices for translation regions to be configured in the ATU */
enum atu_regions_idx {
    /* ATU region to access CMN CFGM */
    ATU_REGION_IDX_CMN = 0,
    /* ATU region to access AP Cluster Utility space */
    ATU_REGION_IDX_CLUSTER_UTIL,
    /* ATU region to access AP shared SRAM */
    ATU_REGION_IDX_SHARED_SRAM,
    /* ATU region to GPC SMMU register space */
    ATU_REGION_IDX_GPC_SMMU,
    /* ATU region to RSM SRAM region */
    ATU_REGION_IDX_RSM_SRAM,
    /* ATU region count */
    ATU_REGION_IDX_COUNT,
};

static struct atu_region_map atu_regions[ATU_REGION_IDX_COUNT] = {
    [ATU_REGION_IDX_CMN] = {
        .region_owner_id = FWK_ID_MODULE_INIT(FWK_MODULE_IDX_SCP_PLATFORM),
        .log_addr_base = SCP_ATW1_CMN_BASE,
        .phy_addr_base = 0x100000000,
        .region_size = SCP_ATW1_CMN_SIZE,
        .attributes = ATU_ENCODE_ATTRIBUTES_ROOT_PAS,
    },
    [ATU_REGION_IDX_CLUSTER_UTIL] = {
        .region_owner_id = FWK_ID_MODULE_INIT(FWK_MODULE_IDX_SCP_PLATFORM),
        .log_addr_base = SCP_ATW0_LCP_AND_CLUSTER_UTILITY_BASE,
        .phy_addr_base = 0x200000000,
        .region_size = SCP_ATW0_LCP_AND_CLUSTER_UTILITY_SIZE,
        .attributes = ATU_ENCODE_ATTRIBUTES_ROOT_PAS,
    },
    [ATU_REGION_IDX_SHARED_SRAM] = {
        .region_owner_id = FWK_ID_MODULE_INIT(FWK_MODULE_IDX_SCP_PLATFORM),
        .log_addr_base = SCP_ATW0_AP_PERIPHERAL_SRAM_BASE,
        .phy_addr_base = 0x00000000,
        .region_size = SCP_ATW0_AP_PERIPHERAL_SRAM_SIZE,
        .attributes = ATU_ENCODE_ATTRIBUTES_ROOT_PAS,
    },
    [ATU_REGION_IDX_GPC_SMMU] = {
        .region_owner_id = FWK_ID_MODULE_INIT(FWK_MODULE_IDX_SCP_PLATFORM),
        .log_addr_base = SCP_ATW0_AP_PERIPHERAL_GPC_SMMU_BASE,
        .phy_addr_base = 0x300000000,
        .region_size = SCP_ATW0_AP_PERIPHERAL_GPC_SMMU_SIZE,
        .attributes = ATU_ENCODE_ATTRIBUTES_ROOT_PAS,
    },
    [ATU_REGION_IDX_RSM_SRAM] = {
        .region_owner_id = FWK_ID_MODULE_INIT(FWK_MODULE_IDX_SCP_PLATFORM),
        .log_addr_base = SCP_ATW0_SHARED_SRAM_RSM_BASE,
        .phy_addr_base = RSM_SHARED_SRAM_BASE,
        .region_size = RSM_SHARED_SRAM_SIZE,
        .attributes = ATU_ENCODE_ATTRIBUTES_SECURE_PAS,
    },
};

static const struct fwk_element element_table[MOD_ATU_ELEMENT_COUNT] = {
    [CFGD_MOD_ATU_EIDX_ATU0] = {
        .name = "SCP_ATU",
        .data = &(struct mod_atu_device_config) {
            .is_atu_delegated = false,
            .atu_base = SCP_ATU_BASE,
            .atu_region_config_table = atu_regions,
            .atu_region_count = FWK_ARRAY_SIZE(atu_regions),
        },
    },
    [CFGD_MOD_ATU_EIDX_COUNT] = { 0 },
};

static const struct fwk_element *get_element_table(fwk_id_t module_id)
{
    unsigned int i;
    uint8_t chip_id;

    chip_id =
        ((*(FWK_R unsigned int *)SID_CHIP_ID_REG) & SID_CHIP_ID_CHIP_ID_MASK) >>
        SID_CHIP_ID_CHIP_ID_SHIFT;

    for (i = 0; i < FWK_ARRAY_SIZE(atu_regions); i++) {
        atu_regions[i].phy_addr_base += (chip_id * RDV3_CHIP_ADDR_SPACE);
    }
    return element_table;
}

struct fwk_module_config config_atu = {
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(get_element_table),
};
