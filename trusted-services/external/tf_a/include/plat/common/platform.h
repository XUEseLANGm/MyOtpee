/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TF_A_PLAT_COMMON_PLATFORM_H
#define TF_A_PLAT_COMMON_PLATFORM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Overrides the tf-a version to map the TF-A platform interface to the TS
 * platform interface.
 */
int plat_get_image_source(
	unsigned int image_id,
	uintptr_t *dev_handle,
	uintptr_t *image_spec);

#ifdef __cplusplus
}
#endif

#endif /* TF_A_PLAT_COMMON_PLATFORM_H */
