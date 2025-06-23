/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#ifndef LIBSP_TEST_MOCK_FFA_INTERNAL_API_H_
#define LIBSP_TEST_MOCK_FFA_INTERNAL_API_H_

#include "ffa_internal_api.h"
#include <stdint.h>

void expect_ffa_svc(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
		    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
		    const struct ffa_params *result);

#endif /* LIBSP_TEST_MOCK_FFA_INTERNAL_API_H_ */
