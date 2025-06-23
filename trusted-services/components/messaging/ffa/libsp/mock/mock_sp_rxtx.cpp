// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include "mock_sp_rxtx.h"

void expect_sp_rxtx_buffer_map(void *tx_buffer, const void *rx_buffer,
			       size_t size, sp_result result)
{
	mock().expectOneCall("sp_rxtx_buffer_map")
		.withPointerParameter("tx_buffer", tx_buffer)
		.withConstPointerParameter("rx_buffer", rx_buffer)
		.withUnsignedIntParameter("size", size)
		.andReturnValue(result);
}

sp_result sp_rxtx_buffer_map(void *tx_buffer, const void *rx_buffer,
			     size_t size)
{
	return mock()
		.actualCall("sp_rxtx_buffer_map")
		.withPointerParameter("tx_buffer", tx_buffer)
		.withConstPointerParameter("rx_buffer", rx_buffer)
		.withUnsignedIntParameter("size", size)
		.returnIntValue();
}

void expect_sp_rxtx_buffer_unmap(sp_result result)
{
	mock().expectOneCall("sp_rxtx_buffer_unmap").andReturnValue(result);
}

sp_result sp_rxtx_buffer_unmap(void)
{
	return mock().actualCall("sp_rxtx_buffer_unmap").returnIntValue();
}

void expect_sp_rxtx_buffer_alignment_boundary_get(const uintptr_t *alignment,
						  sp_result result)
{
	mock().expectOneCall("sp_rxtx_buffer_alignment_boundary_get")
		.withOutputParameterReturning("alignment", alignment,
					      sizeof(*alignment))
		.andReturnValue(result);
}

sp_result sp_rxtx_buffer_alignment_boundary_get(uintptr_t *alignment)
{
	return mock()
		.actualCall("sp_rxtx_buffer_alignment_boundary_get")
		.withOutputParameter("alignment", alignment)
		.returnIntValue();
}

void expect_sp_rxtx_buffer_rx_get(const void **buffer, size_t *size,
				  sp_result result)
{
	mock().expectOneCall("sp_rxtx_buffer_rx_get")
		.withOutputParameterReturning("buffer", buffer, sizeof(*buffer))
		.withOutputParameterReturning("size", size, sizeof(*size))
		.andReturnValue(result);
}

sp_result sp_rxtx_buffer_rx_get(const void **buffer, size_t *size)
{
	return mock()
		.actualCall("sp_rxtx_buffer_rx_get")
		.withOutputParameter("buffer", buffer)
		.withOutputParameter("size", size)
		.returnIntValue();
}

void expect_sp_rxtx_buffer_tx_get(void **buffer, size_t *size, sp_result result)
{
	mock().expectOneCall("sp_rxtx_buffer_tx_get")
		.withOutputParameterReturning("buffer", buffer, sizeof(*buffer))
		.withOutputParameterReturning("size", size, sizeof(*size))
		.andReturnValue(result);
}

sp_result sp_rxtx_buffer_tx_get(void **buffer, size_t *size)
{
	return mock()
		.actualCall("sp_rxtx_buffer_tx_get")
		.withOutputParameter("buffer", buffer)
		.withOutputParameter("size", size)
		.returnIntValue();
}
