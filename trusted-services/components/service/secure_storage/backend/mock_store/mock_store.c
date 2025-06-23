/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mock_store.h"
#include <protocols/service/psa/packed-c/status.h>
#include "util.h"
#include <stdlib.h>
#include <string.h>

static struct mock_store_slot *find_slot(struct mock_store *context, uint64_t uid);
static struct mock_store_slot *find_empty_slot(struct mock_store *context);
static void free_slot(struct mock_store_slot *slot);


static psa_status_t mock_store_set(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_length,
                            const void *p_data,
                            uint32_t create_flags)
{
    (void)client_id;

    psa_status_t psa_status = PSA_ERROR_INSUFFICIENT_STORAGE;
    struct mock_store *this_context = (struct mock_store*)context;

    /* Check length limit */
    if (data_length > MOCK_STORE_ITEM_SIZE_LIMIT) return psa_status;

    if (!uid)
        return PSA_ERROR_INVALID_ARGUMENT;

    /* Replace existing or add new item */
    struct mock_store_slot *slot = find_slot(this_context, uid);
    if (slot) {
        if (slot->flags & PSA_STORAGE_FLAG_WRITE_ONCE)
            return PSA_ERROR_NOT_PERMITTED;

        free_slot(slot);
    } else {
        slot = find_empty_slot(this_context);
    }

    if (slot) {
        slot->item = malloc(data_length);

        if (slot->item) {
            slot->uid = uid;
            slot->flags = create_flags;
            slot->len = slot->capacity = data_length;

            memcpy(slot->item, p_data, slot->len);
            psa_status = PSA_SUCCESS;
        }
    }

    return psa_status;
}

static psa_status_t mock_store_get(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_offset,
                            size_t data_size,
                            void *p_data,
                            size_t *p_data_length)
{
    struct mock_store *this_context = (struct mock_store*)context;

    (void)client_id;

    if (!uid)
        return PSA_ERROR_INVALID_ARGUMENT;

    /* Find the item */
    struct mock_store_slot *slot = find_slot(this_context, uid);

    if (!slot)
        return PSA_ERROR_DOES_NOT_EXIST;

    if (slot->len < data_offset)
        return PSA_ERROR_INVALID_ARGUMENT;

    *p_data_length = MIN(slot->len - data_offset, data_size);
    memcpy(p_data, slot->item + data_offset, *p_data_length);

    return PSA_SUCCESS;
}

static psa_status_t mock_store_get_info(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            struct psa_storage_info_t *p_info)
{
    (void)client_id;

    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    struct mock_store *this_context = (struct mock_store*)context;

    if (!uid)
        return PSA_ERROR_INVALID_ARGUMENT;

    /* Find item to get info about */
    struct mock_store_slot *slot = find_slot(this_context, uid);

    if (slot) {
        p_info->capacity = slot->len;
        p_info->size = slot->len;
        p_info->flags = slot->flags;
        psa_status = PSA_SUCCESS;
    }
    else {
        p_info->capacity = 0;
        p_info->size = 0;
        p_info->flags = 0;
    }

    return psa_status;
}

static psa_status_t mock_store_remove(void *context,
                                uint32_t client_id,
                                uint64_t uid)
{
    (void)client_id;

    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    struct mock_store *this_context = (struct mock_store*)context;

    if (!uid)
        return PSA_ERROR_INVALID_ARGUMENT;

    /* Find and remove the item */
    struct mock_store_slot *slot = find_slot(this_context, uid);

    if (slot) {
        if (!(slot->flags & PSA_STORAGE_FLAG_WRITE_ONCE)) {
            free_slot(slot);
            psa_status = PSA_SUCCESS;
        } else {
            psa_status = PSA_ERROR_NOT_PERMITTED;
        }
    }

    return psa_status;
}

static psa_status_t mock_store_create(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t capacity,
                            uint32_t create_flags)
{
    (void)client_id;

    psa_status_t psa_status = PSA_ERROR_ALREADY_EXISTS;
    struct mock_store *this_context = (struct mock_store*)context;
    struct mock_store_slot *slot;

    slot = find_slot(this_context, uid);

    if (!slot) {

        slot = find_empty_slot(this_context);

        if (slot) {

            slot->item = malloc(capacity);

            if (slot->item) {

                slot->uid = uid;
                slot->flags = create_flags;
                slot->capacity = capacity;
                slot->len = 0;

                memset(slot->item, 0, slot->capacity);
                psa_status = PSA_SUCCESS;
            }
            else  {

                psa_status = PSA_ERROR_INSUFFICIENT_STORAGE;
            }
        }
    }

    return psa_status;
}

static psa_status_t mock_store_set_extended(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_offset,
                            size_t data_length,
                            const void *p_data)
{
    (void)client_id;

    psa_status_t psa_status = PSA_ERROR_DOES_NOT_EXIST;
    struct mock_store *this_context = (struct mock_store*)context;
    struct mock_store_slot *slot;

    slot = find_slot(this_context, uid);

    if (slot && slot->item) {

        if (p_data && slot->capacity >= data_offset + data_length) {

            memcpy(&slot->item[data_offset], p_data, data_length);

            if (data_offset + data_length > slot->len) slot->len = data_offset + data_length;

            psa_status = PSA_SUCCESS;
        }
        else  {

            psa_status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return psa_status;
}

static uint32_t mock_store_get_support(void *context,
                            uint32_t client_id)
{
    (void)context;
    (void)client_id;

    return PSA_STORAGE_SUPPORT_SET_EXTENDED;
}


struct storage_backend *mock_store_init(struct mock_store *context)
{
    for (int i = 0; i < MOCK_STORE_NUM_SLOTS; ++i) {

        context->slots[i].len = 0;
        context->slots[i].capacity = 0;
        context->slots[i].flags = 0;
        context->slots[i].uid = (uint64_t)(-1);
        context->slots[i].item = NULL;
    }

    static const struct storage_backend_interface interface =
    {
        mock_store_set,
        mock_store_get,
        mock_store_get_info,
        mock_store_remove,
        mock_store_create,
        mock_store_set_extended,
        mock_store_get_support
    };

    context->backend.context = context;
    context->backend.interface = &interface;

    return &context->backend;
}

void mock_store_deinit(struct mock_store *context)
{
    mock_store_reset(context);
}

void mock_store_reset(struct mock_store *context)
{
    for (int i = 0; i < MOCK_STORE_NUM_SLOTS; ++i)
        free_slot(&context->slots[i]);
}

bool mock_store_exists(const struct mock_store *context, uint64_t uid)
{
    bool exists = false;

    for (int i = 0; !exists && i < MOCK_STORE_NUM_SLOTS; ++i) {
        exists = context->slots[i].item && (context->slots[i].uid == uid);
    }

    return exists;
}

size_t mock_store_num_items(const struct mock_store *context)
{
    size_t count = 0;

    for (int i = 0; i < MOCK_STORE_NUM_SLOTS; ++i) {
        if (context->slots[i].item) ++count;
    }

    return count;
}

static struct mock_store_slot *find_slot(struct mock_store *context, uint64_t uid)
{
    struct mock_store_slot *slot = NULL;

    for (int i = 0; i < MOCK_STORE_NUM_SLOTS; ++i) {
        if (context->slots[i].item && (context->slots[i].uid == uid)) {
            slot = &context->slots[i];
            break;
        }
    }

    return slot;
}

static struct mock_store_slot *find_empty_slot(struct mock_store *context)
{
    struct mock_store_slot *slot = NULL;

    for (int i = 0; i < MOCK_STORE_NUM_SLOTS; ++i) {
        if (!context->slots[i].item) {
            slot = &context->slots[i];
            break;
        }
    }

    return slot;
}

static void free_slot(struct mock_store_slot *slot)
{
    if (slot->item) {
        free(slot->item);
        slot->len = 0;
        slot->capacity = 0;
        slot->flags = 0;
        slot->uid = (uint64_t)(-1);
        slot->item = NULL;
    }
}
