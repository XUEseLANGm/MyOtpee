/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEST_RUNNER_PROVIDER_SERIALIZER_H
#define TEST_RUNNER_PROVIDER_SERIALIZER_H

#include "rpc/common/endpoint/rpc_service_interface.h"
#include <service/test_runner/common/test_runner.h>

/* Provides a common interface for parameter serialization operations
 * for the test_runner service provider.  Allows alternative serialization
 * protocols to be used without hard-wiring a particular protocol
 * into the service provider code.  A concrete serializer must
 * implement this interface.
 */
struct test_runner_provider_serializer {

	/* Operation: run_tests */
	rpc_status_t (*deserialize_run_tests_req)(const struct rpc_buffer *req_buf,
		struct test_spec *test_spec);

	rpc_status_t (*serialize_run_tests_resp)(struct rpc_buffer *resp_buf,
		const struct test_summary *summary,
		const struct test_result *results);

	/* Operation: list_tests */
	rpc_status_t (*deserialize_list_tests_req)(const struct rpc_buffer *req_buf,
		struct test_spec *test_spec);

	rpc_status_t (*serialize_list_tests_resp)(struct rpc_buffer *resp_buf,
		const struct test_summary *summary,
		const struct test_result *results);
};

#endif /* TEST_RUNNER_PROVIDER_SERIALIZER_H */
