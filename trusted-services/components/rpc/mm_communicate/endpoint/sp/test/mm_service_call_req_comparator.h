/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MM_SERVICE_CALL_REQ_COMPARATOR_H_
#define MM_SERVICE_CALL_REQ_COMPARATOR_H_

#include <CppUTestExt/MockSupport.h>
#include <string.h>
#include "components/rpc/common/test/rpc_buffer_comparator.h"
#include "../mm_communicate_call_ep.h"

class mm_service_call_req_comparator : public MockNamedValueComparator
{
public:
	virtual bool isEqual(const void *object1, const void *object2)
	{
		struct mm_service_call_req *req1 = (struct mm_service_call_req *)object1;
		struct mm_service_call_req *req2 = (struct mm_service_call_req *)object2;
		rpc_buffer_comparator buf_comparator_normal;
		rpc_buffer_comparator buf_comparator_ignore_data_len(
			rpc_buffer_comparator::mode_ignore_data_len);

		return memcmp(req1->guid, req2->guid, sizeof(*req1->guid))  == 0 &&
			buf_comparator_normal.isEqual(&req1->req_buf, &req2->req_buf) &&
			buf_comparator_ignore_data_len.isEqual(&req1->resp_buf, &req2->resp_buf);
	}

	// LCOV_EXCL_START
	virtual SimpleString valueToString(const void *object)
	{
		struct mm_service_call_req *req = (struct mm_service_call_req *)object;
		rpc_buffer_comparator buf_comparator_normal;
		rpc_buffer_comparator buf_comparator_ignore_data_len(
			rpc_buffer_comparator::mode_ignore_data_len);
		SimpleString req_buf_str = buf_comparator_normal.valueToString(&req->req_buf);
		SimpleString resp_buf_str =
			buf_comparator_ignore_data_len.valueToString(&req->resp_buf);
		SimpleString uuid_str = StringFromBinary((const unsigned char *)req->guid,
							 sizeof(*req->guid));

		return StringFromFormat("guid = %s, req_buf = %s, resp_buf = %s",
					uuid_str.asCharString(), req_buf_str.asCharString(),
					resp_buf_str.asCharString());
	}
	// LCOV_EXCL_STOP
};

#endif /* MM_SERVICE_CALL_REQ_COMPARATOR_H_ */
