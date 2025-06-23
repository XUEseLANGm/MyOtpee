// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#include "mock_ffa_internal_api.h"
#include <CppUTestExt/MockSupport.h>

void expect_ffa_svc(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
		    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
		    const struct ffa_params *result)
{
	mock().expectOneCall("ffa_svc")
		.withUnsignedLongIntParameter("a0", a0)
		.withUnsignedLongIntParameter("a1", a1)
		.withUnsignedLongIntParameter("a2", a2)
		.withUnsignedLongIntParameter("a3", a3)
		.withUnsignedLongIntParameter("a4", a4)
		.withUnsignedLongIntParameter("a5", a5)
		.withUnsignedLongIntParameter("a6", a6)
		.withUnsignedLongIntParameter("a7", a7)
		.withOutputParameterReturning("result", result,
					      sizeof(*result));
}

void ffa_svc(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
	     uint64_t a5, uint64_t a6, uint64_t a7, struct ffa_params *result)
{
	mock().actualCall("ffa_svc")
		.withUnsignedLongIntParameter("a0", a0)
		.withUnsignedLongIntParameter("a1", a1)
		.withUnsignedLongIntParameter("a2", a2)
		.withUnsignedLongIntParameter("a3", a3)
		.withUnsignedLongIntParameter("a4", a4)
		.withUnsignedLongIntParameter("a5", a5)
		.withUnsignedLongIntParameter("a6", a6)
		.withUnsignedLongIntParameter("a7", a7)
		.withOutputParameter("result", result);
}
