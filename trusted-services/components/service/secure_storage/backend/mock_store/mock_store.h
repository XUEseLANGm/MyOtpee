/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MOCK_STORE_H
#define MOCK_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MOCK_STORE_NUM_SLOTS        (100)
#define MOCK_STORE_ITEM_SIZE_LIMIT  (10000)

struct mock_store_slot
{
    uint64_t uid;
    uint32_t flags;
    size_t len;
    size_t capacity;
    uint8_t *item;
};

struct mock_store
{
    struct storage_backend backend;
    struct mock_store_slot slots[MOCK_STORE_NUM_SLOTS];
};

struct storage_backend *mock_store_init(struct mock_store *context);
void mock_store_deinit(struct mock_store *context);

/* Test support methods */
void mock_store_reset(struct mock_store *context);
bool mock_store_exists(const struct mock_store *context, uint64_t uid);
size_t mock_store_num_items(const struct mock_store *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MOCK_STORE_H */
