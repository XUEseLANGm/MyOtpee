/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEST_RUNNER_PROVIDER_H
#define TEST_RUNNER_PROVIDER_H

#include "components/rpc/common/endpoint/rpc_service_interface.h"
#include <service/common/provider/service_provider.h>
#include <service/test_runner/provider/serializer/test_runner_provider_serializer.h>
#include <protocols/rpc/common/packed-c/encoding.h>
#include "test_runner_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

/* test_runner_provider serice provider state */
struct test_runner_provider
{
    struct service_provider base_provider;
    const struct test_runner_provider_serializer *serializers[TS_RPC_ENCODING_LIMIT];
    struct test_runner_backend *backend_list;
};

struct rpc_service_interface *test_runner_provider_init(struct test_runner_provider *context);

void test_runner_provider_deinit(struct test_runner_provider *context);

void test_runner_provider_register_serializer(struct test_runner_provider *context,
                    unsigned int encoding, const struct test_runner_provider_serializer *serializer);

void test_runner_provider_register_backend(struct test_runner_provider *context,
                    struct test_runner_backend *backend);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CPPUTEST_TEST_RUNNER_PROVIDER_H */
