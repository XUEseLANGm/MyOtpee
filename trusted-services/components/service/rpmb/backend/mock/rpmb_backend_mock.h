/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_BACKEND_MOCK_H_
#define RPMB_BACKEND_MOCK_H_

#include "../rpmb_backend.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Mock RPMB backend
 *
 * Backend for testing purposes
 */
struct rpmb_backend_mock {
	struct rpmb_backend backend;
};

struct rpmb_backend *rpmb_backend_mock_init(struct rpmb_backend_mock *context);
void rpmb_backend_mock_deinit(struct rpmb_backend_mock *context);

void rpmb_backend_mock_expect_get_dev_info(void *context, uint32_t dev_id,
					   const struct rpmb_dev_info *dev_info,
					   psa_status_t result);

void rpmb_backend_mock_expect_data_request(
	void *context, uint32_t dev_id, const struct rpmb_data_frame *request_frames,
	size_t request_frame_count, const struct rpmb_data_frame *response_frames,
	size_t response_frame_count_in, size_t *response_frame_count_out, psa_status_t result);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RPMB_BACKEND_MOCK_H_ */
