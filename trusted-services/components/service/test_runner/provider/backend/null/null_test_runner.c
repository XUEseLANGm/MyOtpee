/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <service/test_runner/provider/test_runner_backend.h>

/**
 * The null backend is a non-existent test_runner.  An implementation of
 * the test_runner_register_default_backend() function is provided but it does
 * nothing.  This component should be used in deployments where there is
 * no need for a default test_runner.
 */
void test_runner_register_default_backend(struct test_runner_provider *context)
{
    /* Don't register anything */
    (void)context;
}