/*
 * Arm SCP/MCP Software
 * Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *     Configuration data for module 'sid'.
 */

#include "scp_css_mmap.h"

#include <mod_sid.h>

#include <fwk_element.h>
#include <fwk_id.h>
#include <fwk_module.h>

#if (PLATFORM_VARIANT == 0 || PLATFORM_VARIANT == 2)
#    define RD_V3_PART_NUMBER 0x7EE
#elif (PLATFORM_VARIANT == 1)
#    define RD_V3_PART_NUMBER 0x7F9
#else
#    error "Unsupported platform variant"
#endif

/* Module 'sid' element count */
#define MOD_SID_ELEMENT_COUNT 2

static const struct fwk_element subsystem_table[MOD_SID_ELEMENT_COUNT] = {
    { .name = "RD-V3",
      .data =
          &(struct mod_sid_subsystem_config){
              .part_number = RD_V3_PART_NUMBER,
          } },
    { 0 },
};

static const struct fwk_element *get_subsystem_table(fwk_id_t id)
{
    return subsystem_table;
}

const struct fwk_module_config config_sid = {
    .data = &(struct mod_sid_config) {
        .sid_base = SCP_SID_BASE,
        .valid_pcid_registers =
            MOD_PCID_REGISTER_PID0 |
            MOD_PCID_REGISTER_PID1 |
            MOD_PCID_REGISTER_PID2 |
            MOD_PCID_REGISTER_PID3 |
            MOD_PCID_REGISTER_PID4 |
            MOD_PCID_REGISTER_CID0 |
            MOD_PCID_REGISTER_CID1 |
            MOD_PCID_REGISTER_CID2 |
            MOD_PCID_REGISTER_CID3,
        .pcid_expected = {
            .PID0 = 0xBC,
            .PID1 = 0xB0,
            .PID2 = 0x0B,
            .PID3 = 0x00,
            .PID4 = 0x04,
            .CID0 = 0x0D,
            .CID1 = 0xF0,
            .CID2 = 0x05,
            .CID3 = 0xB1,
        },
    },
    .elements = FWK_MODULE_DYNAMIC_ELEMENTS(get_subsystem_table),
};
