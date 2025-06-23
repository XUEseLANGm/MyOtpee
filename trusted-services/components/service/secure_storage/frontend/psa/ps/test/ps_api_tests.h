/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PS_API_TESTS_H
#define PS_API_TESTS_H

/*
 * API level tests for accessing a secure store via the PSA Protected
 * Storage API.  Test scenarios are intended to be reused with different
 * storage backends.
 */
class ps_api_tests
{
public:

    static void set();
    static void createAndSetExtended();
};

#endif /* ITS_API_TESTS_H */
