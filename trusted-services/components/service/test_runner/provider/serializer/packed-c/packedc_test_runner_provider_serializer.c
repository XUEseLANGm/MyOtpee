/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "packedc_test_runner_provider_serializer.h"

#include <common/tlv/tlv.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/test_runner/packed-c/list_tests.h>
#include <protocols/service/test_runner/packed-c/run_tests.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Common rerialization methods used for different operations */
static rpc_status_t deserialize_test_spec(const struct rpc_buffer *req_buf,
					  struct test_spec *test_spec)
{
	struct tlv_const_iterator req_iter;
	struct tlv_record decoded_record;

	test_spec->name[0] = 0;
	test_spec->group[0] = 0;

	tlv_const_iterator_begin(&req_iter, (uint8_t *)req_buf->data, req_buf->data_length);

	if (tlv_find_decode(&req_iter, TS_TEST_RUNNER_TEST_SPEC_TAG_NAME, &decoded_record)) {
		if ((decoded_record.length > 0) && (decoded_record.length < TEST_NAME_MAX_LEN)) {
			memcpy(test_spec->name, decoded_record.value, decoded_record.length);
			test_spec->name[decoded_record.length] = 0;
		}
	}

	if (tlv_find_decode(&req_iter, TS_TEST_RUNNER_TEST_SPEC_TAG_GROUP, &decoded_record)) {
		if ((decoded_record.length > 0) && (decoded_record.length < TEST_GROUP_MAX_LEN)) {
			memcpy(test_spec->group, decoded_record.value, decoded_record.length);
			test_spec->group[decoded_record.length] = 0;
		}
	}

	return TS_RPC_CALL_ACCEPTED;
}

static uint8_t *serialize_test_result(const struct test_result *result, size_t *serialized_len)
{
	uint8_t *out_buf;
	size_t fixed_len = sizeof(struct ts_test_runner_test_result);
	size_t required_space = fixed_len;
	size_t name_len = strlen(result->name);
	size_t group_len = strlen(result->group);

	if (name_len)
		required_space += tlv_required_space(name_len);
	if (group_len)
		required_space += tlv_required_space(group_len);
	if (result->run_state == TEST_RUN_STATE_FAILED)
		required_space += tlv_required_space(sizeof(struct ts_test_runner_test_failure));

	*serialized_len = required_space;

	out_buf = malloc(required_space);

	if (out_buf) {
		struct ts_test_runner_test_result result_msg;
		struct tlv_iterator tlv_iter;

		result_msg.run_state = result->run_state;

		memcpy(out_buf, &result_msg, fixed_len);

		tlv_iterator_begin(&tlv_iter, (uint8_t *)out_buf + fixed_len,
				   required_space - fixed_len);

		if (name_len) {
			struct tlv_record record;

			record.tag = TS_TEST_RUNNER_TEST_RESULT_TAG_NAME;
			record.length = name_len;
			record.value = (const uint8_t *)result->name;
			tlv_encode(&tlv_iter, &record);
		}

		if (group_len) {
			struct tlv_record record;

			record.tag = TS_TEST_RUNNER_TEST_RESULT_TAG_GROUP;
			record.length = group_len;
			record.value = (const uint8_t *)result->group;
			tlv_encode(&tlv_iter, &record);
		}

		if (result->run_state == TEST_RUN_STATE_FAILED) {
			struct ts_test_runner_test_failure serialized_failure;
			struct tlv_record record;

			serialized_failure.line_num = result->failure.line_num;
			serialized_failure.info = result->failure.info;

			record.tag = TS_TEST_RUNNER_TEST_RESULT_TAG_FAILURE;
			record.length = sizeof(serialized_failure);
			record.value = (const uint8_t *)&serialized_failure;
			tlv_encode(&tlv_iter, &record);
		}
	}

	return out_buf;
}

static rpc_status_t serialize_test_results(struct rpc_buffer *resp_buf,
					   const struct test_summary *summary,
					   const struct test_result *results)
{
	size_t space_used = 0;
	rpc_status_t rpc_status = TS_RPC_CALL_ACCEPTED;

	/* Serialize fixed size summary */
	struct ts_test_runner_result_summary summary_msg;
	size_t fixed_len = sizeof(struct ts_test_runner_result_summary);

	summary_msg.num_tests = summary->num_tests;
	summary_msg.num_passed = summary->num_passed;
	summary_msg.num_failed = summary->num_failed;

	if (fixed_len + space_used <= resp_buf->size) {
		memcpy((uint8_t *)resp_buf->data + space_used, &summary_msg, fixed_len);
		space_used += fixed_len;

		/* Serialize test result objects */
		struct tlv_iterator resp_iter;

		tlv_iterator_begin(&resp_iter, (uint8_t *)resp_buf->data + space_used,
				   resp_buf->size - space_used);

		for (size_t i = 0;
		     (i < summary->num_results) && (rpc_status == TS_RPC_CALL_ACCEPTED); ++i) {
			size_t serialised_len;
			uint8_t *serialize_buf =
				serialize_test_result(&results[i], &serialised_len);

			if (serialize_buf) {
				struct tlv_record result_record;

				result_record.tag = TS_TEST_RUNNER_TEST_RESULT_TAG;
				result_record.length = serialised_len;
				result_record.value = serialize_buf;

				if (tlv_encode(&resp_iter, &result_record)) {
					space_used += tlv_required_space(serialised_len);
				} else {
					/* Insufficient buffer space */
					rpc_status = RPC_ERROR_RESOURCE_FAILURE;
				}

				free(serialize_buf);
			}
		}
	}

	resp_buf->data_length = space_used;

	return rpc_status;
}

/* Operation: run_tests */
static rpc_status_t deserialize_run_tests_req(const struct rpc_buffer *req_buf,
					      struct test_spec *test_spec)
{
	return deserialize_test_spec(req_buf, test_spec);
}

static rpc_status_t serialize_run_tests_resp(struct rpc_buffer *resp_buf,
					     const struct test_summary *summary,
					     const struct test_result *results)
{
	return serialize_test_results(resp_buf, summary, results);
}

/* Operation: list_tests */
static rpc_status_t deserialize_list_tests_req(const struct rpc_buffer *req_buf,
					       struct test_spec *test_spec)
{
	return deserialize_test_spec(req_buf, test_spec);
}

static rpc_status_t serialize_list_tests_resp(struct rpc_buffer *resp_buf,
					      const struct test_summary *summary,
					      const struct test_result *results)
{
	return serialize_test_results(resp_buf, summary, results);
}

/* Singleton method to provide access to the serializer instance */
const struct test_runner_provider_serializer *packedc_test_runner_provider_serializer_instance(void)
{
	static const struct test_runner_provider_serializer instance = {
		deserialize_run_tests_req, serialize_run_tests_resp, deserialize_list_tests_req,
		serialize_list_tests_resp
	};

	return &instance;
}
