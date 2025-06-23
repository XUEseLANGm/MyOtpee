/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef CALL_REQ_COMPARATOR_H_
#define CALL_REQ_COMPARATOR_H_

#include <CppUTestExt/MockSupport.h>
#include <inttypes.h>
#include "rpc_buffer_comparator.h"

class rpc_request_comparator : public MockNamedValueComparator
{
public:
	enum check_mode {
		mode_normal = 0,
		mode_ignore_opstatus
	};

	explicit rpc_request_comparator(check_mode mode) : mode(mode)
	{
	}

	virtual bool isEqual(const void *object1, const void *object2)
	{
		struct rpc_request *req1 = (struct rpc_request *)object1;
		struct rpc_request *req2 = (struct rpc_request *)object2;
		rpc_buffer_comparator buf_comparator_normal;
		rpc_buffer_comparator buf_comparator_ignore_data_len(
			rpc_buffer_comparator::mode_ignore_data_len);

		return (req1->source_id == req2->source_id) &&
			(req1->interface_id == req2->interface_id) &&
			(req1->opcode == req2->opcode) &&
			(req1->client_id == req2->client_id) &&
			(mode == mode_ignore_opstatus || req1->service_status == req2->service_status) &&
			buf_comparator_normal.isEqual(&req1->request, &req2->request) &&
			buf_comparator_ignore_data_len.isEqual(&req1->response, &req2->response);
	}

	// LCOV_EXCL_START
	virtual SimpleString valueToString(const void *object)
	{
		struct rpc_request *req = (struct rpc_request *)object;
		rpc_buffer_comparator buf_comparator_normal;
		rpc_buffer_comparator buf_comparator_ignore_data_len(
			rpc_buffer_comparator::mode_ignore_data_len);
		SimpleString req_buf_str = buf_comparator_normal.valueToString(&req->request);
		SimpleString resp_buf_str =
			buf_comparator_ignore_data_len.valueToString(&req->response);

		return StringFromFormat("caller_id = 0x%" PRIx32 ", interface_id = %" PRIu32 ", " \
					"opcode = %" PRIu32 ", encoding = %" PRIu32 ", " \
					"opstatus = 0x%" PRIx64 "%s, req_buf = %s, " \
					"resp_buf = %s",
					req->source_id, req->interface_id, req->opcode,
					req->client_id, req->service_status,
					(mode == mode_ignore_opstatus) ? " (ignore)" : "",
					req_buf_str.asCharString(), resp_buf_str.asCharString());
	}
	// LCOV_EXCL_STOP

private:
	check_mode mode;
};

#endif /* CALL_REQ_COMPARATOR_H_ */
