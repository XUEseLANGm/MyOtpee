/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "test_runner_client.h"
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/test_runner/packed-c/opcodes.h>
#include <protocols/service/test_runner/packed-c/status.h>
#include <protocols/service/test_runner/packed-c/run_tests.h>
#include <protocols/service/test_runner/packed-c/list_tests.h>
#include <rpc_caller.h>
#include <common/tlv/tlv.h>
#include <cstddef>
#include <cstring>
#include <string>

test_runner_client::test_runner_client() :
    m_client()
{
    service_client_init(&m_client, NULL);
}

test_runner_client::test_runner_client(struct rpc_caller_session *session) :
    m_client()
{
    service_client_init(&m_client, session);
}

test_runner_client::~test_runner_client()
{
    service_client_deinit(&m_client);
}

void test_runner_client::set_caller(struct rpc_caller_session *session)
{
    m_client.session = session;
}

int test_runner_client::err_rpc_status() const
{
    return m_client.rpc_status;
}

int test_runner_client::run_tests(
    const struct test_spec &spec,
    struct test_summary &summary,
    std::vector<struct test_result> &results)
{
    return iterate_over_tests(spec, false, summary, results);
}

int test_runner_client::list_tests(
    const struct test_spec &spec,
    struct test_summary &summary,
    std::vector<struct test_result> &results)
{
    return iterate_over_tests(spec, true, summary, results);
}

int test_runner_client::iterate_over_tests(
    const struct test_spec &spec, bool list_only,
    struct test_summary &summary,
    std::vector<struct test_result> &results)
{
    int test_status = TS_TEST_RUNNER_STATUS_ERROR;
    m_client.rpc_status = RPC_ERROR_RESOURCE_FAILURE;
    rpc_call_handle call_handle;
    uint8_t *req_buf;
    std::vector<uint8_t> req_param;

    serialize_test_spec(req_param, spec);

    size_t req_len = req_param.size();
    size_t resp_len = 1024;
    call_handle = rpc_caller_session_begin(m_client.session, &req_buf, req_len, resp_len);

    if (call_handle) {

        uint8_t *resp_buf;
        size_t resp_len;
        service_status_t service_status;

        memcpy(req_buf, req_param.data(), req_len);

        uint32_t opcode = (list_only) ?
            TS_TEST_RUNNER_OPCODE_LIST_TESTS :
            TS_TEST_RUNNER_OPCODE_RUN_TESTS;

        m_client.rpc_status = rpc_caller_session_invoke(call_handle,
            opcode, &resp_buf, &resp_len, &service_status);

        if (m_client.rpc_status == TS_RPC_CALL_ACCEPTED) {

            test_status = service_status;

            if (test_status == TS_TEST_RUNNER_STATUS_SUCCESS) {

                test_status = deserialize_results(resp_buf, resp_len, summary, results);
            }
        }

        rpc_caller_session_end(call_handle);
    }

    return test_status;
}

void test_runner_client::serialize_test_spec(
    std::vector<uint8_t> &serialized_data,
    const struct test_spec &spec) const
{
    size_t name_len = strlen(spec.name);
    size_t group_len = strlen(spec.group);
    size_t tlv_space = 0;

    /* First determine buffer space needed for TLV parameters */
    if (name_len)  tlv_space += tlv_required_space(name_len);
    if (group_len) tlv_space += tlv_required_space(group_len);

    /* Extend the params vector and write the tlv records */
    if (tlv_space) {

        serialized_data.resize(tlv_space);
        struct tlv_iterator iter;
        uint8_t *buf = serialized_data.data();

        tlv_iterator_begin(&iter, buf, tlv_space);

        if (name_len) {

            struct tlv_record record;
            record.tag = TS_TEST_RUNNER_TEST_SPEC_TAG_NAME;
            record.length = name_len;
            record.value = (const uint8_t*)spec.name;
            tlv_encode(&iter, &record);
        }

        if (group_len) {

            struct tlv_record record;
            record.tag = TS_TEST_RUNNER_TEST_SPEC_TAG_GROUP;
            record.length = group_len;
            record.value = (const uint8_t*)spec.group;
            tlv_encode(&iter, &record);
        }
    }
}

int test_runner_client::deserialize_results(
    const uint8_t *resp_buf, size_t resp_len,
    struct test_summary &summary,
    std::vector<struct test_result> &results) const
{
    int test_status = TS_TEST_RUNNER_STATUS_SUCCESS;
    size_t fixed_size = sizeof(ts_test_runner_result_summary);

    if (resp_len >= fixed_size) {

        /* Deserialize fixed size summary structure */
        struct ts_test_runner_result_summary packed_summary;
        memcpy(&packed_summary, resp_buf, fixed_size);

        summary.num_tests = packed_summary.num_tests;
        summary.num_passed = packed_summary.num_passed;
        summary.num_failed = packed_summary.num_failed;
        summary.num_results = 0;

        /* Deserialize any test result records */
        struct tlv_const_iterator tlv_iter;
        struct tlv_record result_record;
        tlv_const_iterator_begin(&tlv_iter, &resp_buf[fixed_size], resp_len - fixed_size);

        while (tlv_find_decode(&tlv_iter, TS_TEST_RUNNER_TEST_RESULT_TAG, &result_record)) {

            struct test_result result;

            test_status = deserialize_result(result_record.value, result_record.length, result);

            if (test_status == TS_TEST_RUNNER_STATUS_SUCCESS) {

                results.push_back(result);
                ++summary.num_results;
            }
            else {
                /* Failed to decode result record */
                break;
            }
        }
    }
    else {
        /* Failed to mandatory test summary */
        test_status = TS_TEST_RUNNER_STATUS_INVALID_TEST_RESULTS;
    }

    return test_status;
}

int test_runner_client::deserialize_result(
    const uint8_t *value_buf, size_t value_len,
    struct test_result &result) const
{
    int test_status = TS_TEST_RUNNER_STATUS_SUCCESS;
    size_t fixed_size = sizeof(ts_test_runner_test_result);

    if (value_len >= fixed_size) {

        struct ts_test_runner_test_result packed_result;
        memcpy(&packed_result, value_buf, fixed_size);

        memset(&result, 0, sizeof(result));
        result.run_state = (enum test_run_state)packed_result.run_state;

        /* Deserialize name and group if present */
        struct tlv_const_iterator req_iter;
        struct tlv_record decoded_record;

        tlv_const_iterator_begin(&req_iter, &value_buf[fixed_size], value_len - fixed_size);

        if (tlv_find_decode(&req_iter, TS_TEST_RUNNER_TEST_RESULT_TAG_NAME, &decoded_record)) {

            if ((decoded_record.length > 0) && (decoded_record.length < TEST_NAME_MAX_LEN)) {

                memcpy(result.name, decoded_record.value, decoded_record.length);
                result.name[decoded_record.length] = 0;
            }
        }

        if (tlv_find_decode(&req_iter, TS_TEST_RUNNER_TEST_RESULT_TAG_GROUP, &decoded_record)) {

            if ((decoded_record.length > 0) && (decoded_record.length < TEST_GROUP_MAX_LEN)) {

                memcpy(result.group, decoded_record.value, decoded_record.length);
                result.group[decoded_record.length] = 0;
            }
        }

        if (tlv_find_decode(&req_iter, TS_TEST_RUNNER_TEST_RESULT_TAG_FAILURE, &decoded_record)) {

            if (decoded_record.length == sizeof(ts_test_runner_test_failure)) {

                struct ts_test_runner_test_failure deserialized_failure;
                memcpy(&deserialized_failure, decoded_record.value, decoded_record.length);
                result.failure.line_num = deserialized_failure.line_num;
                result.failure.info = deserialized_failure.info;
            }
        }
    }
    else {
        /* Invalid test result */
        test_status = TS_TEST_RUNNER_STATUS_INVALID_TEST_RESULTS;
    }

    return test_status;
}
