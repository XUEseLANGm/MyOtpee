/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BOOT_SEED_GENERATOR_H
#define BOOT_SEED_GENERATOR_H

#include <stdbool.h>
#include <stdint.h>
#include <service/attestation/claims/claim_source.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A claim source for generating and accessing a boot seed.
 * The boot seed is a random number that forms an identifier for
 * a particular boot session.  On each re-boot, a new boot seed is
 * generated.  By including the boot seed in an attestation report,
 * reports associated with the same boot session may be identified.
 * Use this claim source in a deployment when no boot seed is passed
 * forward by the boot loader or when no other authoritative source of
 * boot seed is available.
 */
struct boot_seed_generator
{
    struct claim_source base;

    bool is_generated;
    uint8_t boot_seed[32];
};

/**
 * \brief Initializes a struct boot_seed_generator
 *
 * \param[in] instance      The instance to initialze
 *
 * \return The initialize base claim_source structure
 */
struct claim_source *boot_seed_generator_init(struct boot_seed_generator *instance);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BOOT_SEED_GENERATOR_H */
