/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_TEST_RUNNER_STATUS_H
#define TS_TEST_RUNNER_STATUS_H

/**
 * Test runner service level statos codes
 */
enum
{
	/**
	 * Returned if an operation completed successfully.
	 * This doesn't mean that requested tests passed
	 * but rather that the test runner operation
	 * completed normally.
	 */
	TS_TEST_RUNNER_STATUS_SUCCESS = 0,

	/**
	 * Generic error occurred.
	 */
	TS_TEST_RUNNER_STATUS_ERROR = -1,

	/**
	 * Invalid test resuts returned by service provider.
	 */
	TS_TEST_RUNNER_STATUS_INVALID_TEST_RESULTS = -2
};

#endif /* TS_TEST_RUNNER_STATUS_H */
