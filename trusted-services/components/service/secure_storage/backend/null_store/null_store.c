/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "null_store.h"
#include <protocols/service/psa/packed-c/status.h>
#include <stddef.h>

static psa_status_t null_store_set(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_length,
                            const void *p_data,
                            uint32_t create_flags)
{
    (void)context;
    (void)client_id;
    (void)uid;
    (void)data_length;
    (void)p_data;
    (void)create_flags;

    return PSA_ERROR_STORAGE_FAILURE;
}

static psa_status_t null_store_get(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_offset,
                            size_t data_size,
                            void *p_data,
                            size_t *p_data_length)
{
    (void)context;
    (void)client_id;
    (void)uid;
    (void)data_offset;
    (void)data_size;
    (void)p_data;
    (void)p_data_length;

    return PSA_ERROR_STORAGE_FAILURE;
}

static psa_status_t null_store_get_info(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            struct psa_storage_info_t *p_info)
{
    (void)context;
    (void)client_id;
    (void)uid;
    (void)p_info;

    return PSA_ERROR_STORAGE_FAILURE;
}

static psa_status_t null_store_remove(void *context,
                                uint32_t client_id,
                                uint64_t uid)
{
    (void)context;
    (void)client_id;
    (void)uid;

    return PSA_ERROR_STORAGE_FAILURE;
}

static psa_status_t null_store_create(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t capacity,
                            uint32_t create_flags)
{
    (void)context;
    (void)client_id;
    (void)uid;
    (void)capacity;
    (void)create_flags;

    return PSA_ERROR_STORAGE_FAILURE;
}

static psa_status_t null_store_set_extended(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_offset,
                            size_t data_length,
                            const void *p_data)
{
    (void)context;
    (void)client_id;
    (void)uid;
    (void)data_offset;
    (void)data_length;
    (void)p_data;

    return PSA_ERROR_STORAGE_FAILURE;
}

static uint32_t null_store_get_support(void *context,
                            uint32_t client_id)
{
    (void)context;
    (void)client_id;

    return 0;
}


struct storage_backend *null_store_init(struct null_store *context)
{
    static const struct storage_backend_interface interface =
    {
        null_store_set,
        null_store_get,
        null_store_get_info,
        null_store_remove,
        null_store_create,
        null_store_set_extended,
        null_store_get_support
    };

    context->backend.context = context;
    context->backend.interface = &interface;

    return &context->backend;
}

void null_store_deinit(struct null_store *context)
{
    context->backend.context = NULL;
    context->backend.interface = NULL;
}
