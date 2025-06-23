/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SP_CONFIG_LOADER_H
#define SP_CONFIG_LOADER_H

#include <ffa_api.h>
#include <stdbool.h>

/**
 * Loads the secure partition specific configuration passed as
 * SP initialization parameters.
 */
bool sp_config_load(union ffa_boot_info *boot_info);

#endif /* SP_CONFIG_LOADER_H */
