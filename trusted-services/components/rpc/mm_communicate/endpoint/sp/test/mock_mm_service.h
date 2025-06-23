/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MOCK_MM_SERVICE_H_
#define MOCK_MM_SERVICE_H_

#include "../mm_communicate_call_ep.h"

#ifdef __cplusplus
extern "C" {
#endif

void mock_mm_service_init(void);

void expect_mock_mm_service_receive(struct mm_service_interface *iface,
				    const struct mm_service_call_req *req,
				    int64_t result);

int32_t mock_mm_service_receive(struct mm_service_interface *iface,
				struct mm_service_call_req *req);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_MM_SERVICE_H_ */
