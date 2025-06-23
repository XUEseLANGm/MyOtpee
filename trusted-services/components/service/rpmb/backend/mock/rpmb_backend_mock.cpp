/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTestExt/MockSupport.h>
#include "rpmb_backend_mock.h"

void rpmb_backend_mock_expect_get_dev_info(void *context, uint32_t dev_id,
					   const struct rpmb_dev_info *dev_info,
					   psa_status_t result)
{
	mock().expectOneCall("get_dev_info").
		onObject(context).
		withUnsignedIntParameter("dev_id", dev_id).
		withOutputParameterReturning("dev_info", dev_info, sizeof(*dev_info)).
		andReturnValue(result);
}

static psa_status_t rpmb_backend_mock_get_dev_info(void *context, uint32_t dev_id,
						   struct rpmb_dev_info *dev_info)
{
	return mock().actualCall("get_dev_info").
		onObject(context).
		withUnsignedIntParameter("dev_id", dev_id).
		withOutputParameter("dev_info", dev_info).
		returnIntValue();
}

void rpmb_backend_mock_expect_data_request(
	void *context, uint32_t dev_id, const struct rpmb_data_frame *request_frames,
	size_t request_frame_count, const struct rpmb_data_frame *response_frames,
	size_t response_frame_count_in, size_t *response_frame_count_out, psa_status_t result)
{
	size_t request_size = sizeof(*request_frames) * request_frame_count;
	size_t response_size = sizeof(*response_frames) * (*response_frame_count_out);

	mock().expectOneCall("data_request").
		onObject(context).
		withUnsignedIntParameter("dev_id", dev_id).
		withMemoryBufferParameter("request_frames", (const unsigned char *)request_frames,
					  request_size).
		withUnsignedIntParameter("request_frame_count", request_frame_count).
		withOutputParameterReturning("response_frames", response_frames, response_size).
		withUnsignedIntParameter("response_frame_count_in", response_frame_count_in).
		withOutputParameterReturning("response_frame_count_out", response_frame_count_out,
					     sizeof(*response_frame_count_out)).
		andReturnValue(result);
}

static psa_status_t rpmb_backend_mock_data_request(
	void *context, uint32_t dev_id, const struct rpmb_data_frame *request_frames,
	size_t request_frame_count, struct rpmb_data_frame *response_frames,
	size_t *response_frame_count)
{
	size_t request_size = sizeof(*request_frames) * request_frame_count;

	return mock().actualCall("data_request").
		onObject(context).
		withUnsignedIntParameter("dev_id", dev_id).
		withMemoryBufferParameter("request_frames", (const unsigned char *)request_frames,
					  request_size).
		withUnsignedIntParameter("request_frame_count", request_frame_count).
		withOutputParameter("response_frames", response_frames).
		withUnsignedIntParameter("response_frame_count_in", *response_frame_count).
		withOutputParameter("response_frame_count_out", response_frame_count).
		returnIntValue();
}

struct rpmb_backend *rpmb_backend_mock_init(struct rpmb_backend_mock *context)
{
	static const struct rpmb_backend_interface interface = {
		rpmb_backend_mock_get_dev_info,
		rpmb_backend_mock_data_request,
	};

	if (!context)
		return NULL;

	context->backend.context = context;
	context->backend.interface = &interface;

	return &context->backend;
}

void rpmb_backend_mock_deinit(struct rpmb_backend_mock *context)
{
	*context = (struct rpmb_backend_mock){ 0 };
}
