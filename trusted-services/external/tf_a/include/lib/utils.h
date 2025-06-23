/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TF_A_LIB_UTILS_H
#define TF_A_LIB_UTILS_H

#include <stddef.h>
#include <string.h>

/**
 * A stub version of the tf-a lib/utils.h
 */

#ifdef __cplusplus
extern "C" {
#endif

static inline void zeromem(void *mem, size_t length)
{
    memset(mem, 0, length);
}

#ifdef __cplusplus
}
#endif

#endif /* TF_A_LIB_UTILS_H */
