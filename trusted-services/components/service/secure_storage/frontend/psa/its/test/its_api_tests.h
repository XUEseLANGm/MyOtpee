/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef ITS_API_TESTS_H
#define ITS_API_TESTS_H

#include <cstddef>

/*
 * API level tests for accessing a secure store via the PSA Internal
 * Trusted Storage API.  Test scenarios are intended to be reused
 * with different storage backends.
 */
class its_api_tests
{
public:

    static void storeNewItem();
    static void storageLimitTest(size_t size_limit);
};

#endif /* ITS_API_TESTS_H */