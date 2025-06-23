// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include <CppUTest/TestHarness.h>
#include "mock_sp_rxtx.h"
#include <stdint.h>
#include <stdlib.h>

static uint8_t tx_buf[16] = { 0 };
static const uint8_t rx_buf[16] = { 0 };

static void *expected_tx_buffer = tx_buf;
static const void *expected_rx_buffer = rx_buf;
static size_t expected_size = 1234;

TEST_GROUP(mock_sp_rxtx)
{
	TEST_TEARDOWN()
	{
		mock().checkExpectations();
		mock().clear();
	}

	static const sp_result result = -1;
};

TEST(mock_sp_rxtx, sp_rxtx_buffer_map)
{
	expect_sp_rxtx_buffer_map(expected_tx_buffer, expected_rx_buffer,
				  expected_size, result);
	LONGS_EQUAL(result,
		    sp_rxtx_buffer_map(expected_tx_buffer, expected_rx_buffer,
				       expected_size));
}

TEST(mock_sp_rxtx, sp_rxtx_buffer_unmap)
{
	expect_sp_rxtx_buffer_unmap(result);
	LONGS_EQUAL(result, sp_rxtx_buffer_unmap());
}

TEST(mock_sp_rxtx, sp_rxtx_buffer_alignment_boundary_get)
{
	const uintptr_t expected_alignment = 4096;
	uintptr_t alignment = 0;

	expect_sp_rxtx_buffer_alignment_boundary_get(&expected_alignment,
						     result);
	LONGS_EQUAL(result, sp_rxtx_buffer_alignment_boundary_get(&alignment));
	UNSIGNED_LONGLONGS_EQUAL(expected_alignment, alignment);
}

TEST(mock_sp_rxtx, sp_rxtx_buffer_rx_get)
{
	const void *buffer = NULL;
	size_t size = 0;

	expect_sp_rxtx_buffer_rx_get(&expected_rx_buffer, &expected_size,
				     result);
	LONGS_EQUAL(result, sp_rxtx_buffer_rx_get(&buffer, &size));
	POINTERS_EQUAL(expected_rx_buffer, buffer);
	UNSIGNED_LONGLONGS_EQUAL(expected_size, size);
}

TEST(mock_sp_rxtx, sp_rxtx_buffer_tx_get)
{
	void *buffer = NULL;
	size_t size = 0;

	expect_sp_rxtx_buffer_tx_get((void **)&expected_tx_buffer,
				     &expected_size, result);
	LONGS_EQUAL(result, sp_rxtx_buffer_tx_get(&buffer, &size));
	POINTERS_EQUAL(expected_tx_buffer, buffer);
	UNSIGNED_LONGLONGS_EQUAL(expected_size, size);
}
