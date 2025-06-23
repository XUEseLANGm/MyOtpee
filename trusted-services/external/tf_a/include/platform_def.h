/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TF_A_PALTFORM_DEF_H
#define TF_A_PALTFORM_DEF_H

#include <stdbool.h>

/**
 * Provides a set of defaults for values defined by the platform specific
 * 'platform_def.h' file. Deployments may override default definitions.
 */

#ifndef ENABLE_ASSERTIONS
#define ENABLE_ASSERTIONS       true
#endif

#ifndef MAX_IO_HANDLES
#define MAX_IO_HANDLES          (4)
#endif

#ifndef MAX_IO_DEVICES
#define MAX_IO_DEVICES          (4)
#endif

#endif /* TF_A_PALTFORM_DEF_H */
