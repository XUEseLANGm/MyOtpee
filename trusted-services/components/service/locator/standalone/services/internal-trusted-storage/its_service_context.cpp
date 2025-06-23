/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "its_service_context.h"
#include "components/service/secure_storage/frontend/secure_storage_provider/secure_storage_uuid.h"

its_service_context::its_service_context(const char *sn) :
    standalone_service_context(sn),
    m_storage_provider(),
    m_mock_store()
{

}

its_service_context::~its_service_context()
{

}

void its_service_context::do_init()
{
    const rpc_uuid service_uuid = {.uuid = TS_PSA_INTERNAL_TRUSTED_STORAGE_UUID};
    struct storage_backend *storage_backend = mock_store_init(&m_mock_store);
    struct rpc_service_interface *storage_ep =
        secure_storage_provider_init(&m_storage_provider, storage_backend, &service_uuid);

    standalone_service_context::set_rpc_interface(storage_ep);
}

void its_service_context::do_deinit()
{
    secure_storage_provider_deinit(&m_storage_provider);
    mock_store_deinit(&m_mock_store);
}
