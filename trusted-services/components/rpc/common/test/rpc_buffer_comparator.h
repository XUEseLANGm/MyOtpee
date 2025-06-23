/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef RPC_BUFFER_COMPARATOR_H_
#define RPC_BUFFER_COMPARATOR_H_

#include <CppUTestExt/MockSupport.h>
#include "../endpoint/rpc_service_interface.h"

class rpc_buffer_comparator : public MockNamedValueComparator
{
public:
	enum check_mode {
		mode_normal = 0,
		mode_ignore_data_len
	};

	explicit rpc_buffer_comparator(check_mode mode = mode_normal) : mode(mode)
	{
	}

	virtual bool isEqual(const void *object1, const void *object2)
	{
		struct rpc_buffer *buf1 = (struct rpc_buffer *)object1;
		struct rpc_buffer *buf2 = (struct rpc_buffer *)object2;

		return (buf1->data == buf2->data) &&
			(buf1->size == buf2->size) &&
			(mode == mode_ignore_data_len || buf1->data_length == buf2->data_length);
	}

	// LCOV_EXCL_START
	virtual SimpleString valueToString(const void *object)
	{
		struct rpc_buffer *buf = (struct rpc_buffer *)object;

		return StringFromFormat("<size = %zu, data_len = %zu%s, data = %p>",
					buf->size, buf->data_length,
					(mode == mode_ignore_data_len) ? " (ignored)" : "",
					buf->data);
	}
	// LCOV_EXCL_STOP

private:
	check_mode mode;
};

#endif /* RPC_BUFFER_COMPARATOR_H_ */
