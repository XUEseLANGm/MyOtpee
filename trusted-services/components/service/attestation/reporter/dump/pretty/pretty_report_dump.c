/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdio.h>
#include <common/cbor_dump/cbor_dump.h>
#include <protocols/service/attestation/packed-c/eat.h>

int pretty_report_dump(const uint8_t *report, size_t len)
{
    static const struct cbor_dictionary_entry eat_dictionary[] =
    {
        {EAT_ARM_PSA_CLAIM_ID_PROFILE_DEFINITION,       "profile_definition"},
        {EAT_ARM_PSA_CLAIM_ID_CLIENT_ID,                "client_id"},
        {EAT_ARM_PSA_CLAIM_ID_SECURITY_LIFECYCLE,       "security_lifecycle"},
        {EAT_ARM_PSA_CLAIM_ID_IMPLEMENTATION_ID,        "implementation_id"},
        {EAT_ARM_PSA_CLAIM_ID_BOOT_SEED,                "boot_seed"},
        {EAT_ARM_PSA_CLAIM_ID_HW_VERSION,               "hw_version"},
        {EAT_ARM_PSA_CLAIM_ID_SW_COMPONENTS,            "sw_components"},
        {EAT_ARM_PSA_CLAIM_ID_NO_SW_COMPONENTS,         "no_sw_components"},
        {EAT_ARM_PSA_CLAIM_ID_CHALLENGE,                "challenge"},
        {EAT_ARM_PSA_CLAIM_ID_INSTANCE_ID,              "instance_id"},
        {EAT_ARM_PSA_CLAIM_ID_VERIFIER,                 "verifier_id"},
        {EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_TYPE,    "type"},
        {EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_VALUE,   "digest"}
    };

    return cbor_dump(stdout, report, len,
        0, "attestation_report",
        eat_dictionary, sizeof(eat_dictionary)/sizeof(struct cbor_dictionary_entry));
}
