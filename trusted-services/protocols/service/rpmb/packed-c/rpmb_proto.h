/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_PROTO_H
#define RPMB_PROTO_H

#include "components/service/rpmb/backend/rpmb_backend.h"
#include "compiler.h"
#include <stdint.h>

/* Operation GET_DEV_INFO request parameters */
struct rpmb_request_get_dev_info {
	uint32_t dev_id;
} __packed;

/* Operation GET_DEV_INFO response parameters */
struct rpmb_response_get_dev_info {
	struct rpmb_dev_info dev_info;
} __packed;

/* Operation DATA_REQUEST request parameters */
struct rpmb_request_data_request {
	uint32_t dev_id;
	uint32_t request_frame_count;
	uint32_t max_response_frame_count;
	struct rpmb_data_frame request_frames[];
} __packed;

/* Operation DATA_REQUEST response parameters */
struct rpmb_response_data_request {
	uint32_t response_frame_count;
	struct rpmb_data_frame response_frames[];
} __packed;

#define TS_RPMB_OPCODE_GET_DEV_INFO			(0u)
#define TS_RPMB_OPCODE_DATA_REQUEST			(1u)

#endif /* RPMB_PROTO_H */
