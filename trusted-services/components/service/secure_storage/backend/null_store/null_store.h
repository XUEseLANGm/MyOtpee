/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NULL_STORE_H
#define NULL_STORE_H

#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The null_store is intended to be used when an error makes
 * it impossible to initialise a real storage backend.  The
 * null_store provides handlers for the storage_backend
 * interface but returns an error if any are called.  Example
 * error conditions where the null_store cab used are:
 *  - configuration error leading to a partition discovery failure
 *  - a hardware fault
 */
struct null_store
{
    struct storage_backend backend;
};

struct storage_backend *null_store_init(struct null_store *context);
void null_store_deinit(struct null_store *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NULL_STORE_H */
