/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "test_runner_service_context.h"
#include <service/test_runner/provider/serializer/packed-c/packedc_test_runner_provider_serializer.h>

test_runner_service_context::test_runner_service_context(const char *sn) :
    standalone_service_context(sn),
    m_test_runner_provider()
{

}

test_runner_service_context::~test_runner_service_context()
{

}

void test_runner_service_context::do_init()
{
    struct rpc_service_interface *test_runner_ep = test_runner_provider_init(&m_test_runner_provider);

    test_runner_provider_register_serializer(&m_test_runner_provider,
                    TS_RPC_ENCODING_PACKED_C, packedc_test_runner_provider_serializer_instance());

    standalone_service_context::set_rpc_interface(test_runner_ep);
}

void test_runner_service_context::do_deinit()
{
    test_runner_provider_deinit(&m_test_runner_provider);
}
