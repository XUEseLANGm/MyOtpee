/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEST_RUNNER_CLIENT_H
#define TEST_RUNNER_CLIENT_H

#include <cstdint>
#include <vector>
#include <string>
#include <service/test_runner/common/test_runner.h>
#include <service/common/client/service_client.h>

/*
 * Provides a client interface for running remote tests using the test-runner
 * service access protocol.
 */
class test_runner_client
{
public:
    test_runner_client();
    test_runner_client(struct rpc_caller_session *session);
    virtual ~test_runner_client();

    void set_caller(struct rpc_caller_session *session);
    int err_rpc_status() const;

    int run_tests(const struct test_spec &spec,
                struct test_summary &summary,
                std::vector<struct test_result> &results);

    int list_tests(const struct test_spec &spec,
                struct test_summary &summary,
                std::vector<struct test_result> &results);

private:

    int iterate_over_tests(const struct test_spec &spec, bool list_only,
                struct test_summary &summary,
                std::vector<struct test_result> &results);

    void serialize_test_spec(std::vector<uint8_t> &serialized_data,
                const struct test_spec &spec) const;

    int deserialize_results(const uint8_t *resp_buf, size_t resp_len,
                struct test_summary &summary,
                std::vector<struct test_result> &results) const;

    int deserialize_result(const uint8_t *value_buf, size_t value_len,
                struct test_result &result) const;

    struct service_client m_client;
};

#endif /* TEST_RUNNER_CLIENT_H */
