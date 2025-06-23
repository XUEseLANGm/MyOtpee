/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpmb_backend.h"

int rpmb_backend_get_dev_info(struct rpmb_backend *instance, uint32_t dev_id,
			      struct rpmb_dev_info *dev_info)
{
	return instance->interface->get_dev_info(instance->context, dev_id, dev_info);
}

int rpmb_backend_data_request(struct rpmb_backend *instance, uint32_t dev_id,
			      const struct rpmb_data_frame *request_frames,
			      size_t request_frame_count,
			      struct rpmb_data_frame *response_frames, size_t *response_frame_count)
{
	return instance->interface->data_request(instance->context, dev_id, request_frames,
						 request_frame_count, response_frames,
						 response_frame_count);
}
