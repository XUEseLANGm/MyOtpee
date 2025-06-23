/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_TEST_RUNNER_SERVICE_CONTEXT_H
#define STANDALONE_TEST_RUNNER_SERVICE_CONTEXT_H

#include <service/locator/standalone/standalone_service_context.h>
#include <rpc/direct/direct_caller.h>
#include <service/test_runner/provider/test_runner_provider.h>

class test_runner_service_context : public standalone_service_context
{
public:
    test_runner_service_context(const char *sn);
    virtual ~test_runner_service_context();

private:

    void do_init();
    void do_deinit();

    struct test_runner_provider m_test_runner_provider;
};

#endif /* STANDALONE_TEST_RUNNER_SERVICE_CONTEXT_H */
