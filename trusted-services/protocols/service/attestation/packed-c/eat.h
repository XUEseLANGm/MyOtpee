/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * EAT (Entity Attestion Token) definitions used in the PSA attestation
 * report.
 */

#ifndef PROTOCOLS_ATTESTATION_EAT
#define PROTOCOLS_ATTESTATION_EAT

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PSA custom EAT claim IDs
 */
#define EAT_ARM_PSA_CLAIM_ID_BASE                   (-75000)
#define EAT_ARM_PSA_CLAIM_ID_PROFILE_DEFINITION     (EAT_ARM_PSA_CLAIM_ID_BASE - 0)
#define EAT_ARM_PSA_CLAIM_ID_CLIENT_ID              (EAT_ARM_PSA_CLAIM_ID_BASE - 1)
#define EAT_ARM_PSA_CLAIM_ID_SECURITY_LIFECYCLE     (EAT_ARM_PSA_CLAIM_ID_BASE - 2)
#define EAT_ARM_PSA_CLAIM_ID_IMPLEMENTATION_ID      (EAT_ARM_PSA_CLAIM_ID_BASE - 3)
#define EAT_ARM_PSA_CLAIM_ID_BOOT_SEED              (EAT_ARM_PSA_CLAIM_ID_BASE - 4)
#define EAT_ARM_PSA_CLAIM_ID_HW_VERSION             (EAT_ARM_PSA_CLAIM_ID_BASE - 5)
#define EAT_ARM_PSA_CLAIM_ID_SW_COMPONENTS          (EAT_ARM_PSA_CLAIM_ID_BASE - 6)
#define EAT_ARM_PSA_CLAIM_ID_NO_SW_COMPONENTS       (EAT_ARM_PSA_CLAIM_ID_BASE - 7)
#define EAT_ARM_PSA_CLAIM_ID_CHALLENGE              (EAT_ARM_PSA_CLAIM_ID_BASE - 8)
#define EAT_ARM_PSA_CLAIM_ID_INSTANCE_ID            (EAT_ARM_PSA_CLAIM_ID_BASE - 9)
#define EAT_ARM_PSA_CLAIM_ID_VERIFIER               (EAT_ARM_PSA_CLAIM_ID_BASE - 10)

/**
 * SW component EAT claim IDs
 */
#define EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_TYPE  (1)
#define EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_VALUE (2)
#define EAT_SW_COMPONENT_CLAIM_ID_RESERVED          (3)
#define EAT_SW_COMPONENT_CLAIM_ID_VERSION           (4)
#define EAT_SW_COMPONENT_CLAIM_ID_SIGNER_ID         (5)
#define EAT_SW_COMPONENT_CLAIM_ID_MEASUREMENT_DESC  (6)


#ifdef __cplusplus
}
#endif

#endif /* PROTOCOLS_ATTESTATION_EAT */
