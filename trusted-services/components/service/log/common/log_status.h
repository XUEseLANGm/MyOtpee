/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LOG_STATUS_H
#define LOG_STATUS_H

#include <stdint.h>

typedef int32_t log_status_t;

#define LOG_STATUS_SUCCESS	     ((log_status_t)0)
#define LOG_STATUS_GENERIC_ERROR     ((log_status_t)-1)
#define LOG_STATUS_INVALID_PARAMETER ((log_status_t)-2)

#endif /* LOG_STATUS_H */
