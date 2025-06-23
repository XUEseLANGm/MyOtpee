/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TF_A_COMMON_DEBUG_H
#define TF_A_COMMON_DEBUG_H

/**
 * Overrides the tf-a version to avoid a dependency on the tf-a debug environment.
 * Some tf-a components rely on debug.h to bring some standard include files. The
 * following includes provide the missing include files.
 */
#include <stdint.h>

/**
 * Log operations
 */
#define ERROR(...)
#define ERROR_NL()

#define NOTICE(...)
#define WARN(...)

#define INFO(...)

#define VERBOSE(...)

#endif /* TF_A_COMMON_DEBUG_H */
