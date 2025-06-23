/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_BASE_IO_DEV_H
#define MEDIA_BASE_IO_DEV_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Base io_dev definition. An io_dev is a tf-a abstraction used for accessing
 * an underlying storage volume as a single file with posix-like file I/O
 * operations.
 *
 * Export tf-a version with C++ linkage support.
 */
#include <drivers/io/io_storage.h>

#ifdef __cplusplus
}
#endif

#endif /* MEDIA_BASE_IO_DEV_H */
