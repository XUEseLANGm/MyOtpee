/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_TEST_RUNNER_PROVIDER_SERIALIZER_H
#define PACKEDC_TEST_RUNNER_PROVIDER_SERIALIZER_H

#include <service/test_runner/provider/serializer/test_runner_provider_serializer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Singleton method to provide access to the packed-c serializer
 * for the test_runner service provider.
 */
const struct test_runner_provider_serializer *packedc_test_runner_provider_serializer_instance(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PACKEDC_TEST_RUNNER_PROVIDER_SERIALIZER_H */
