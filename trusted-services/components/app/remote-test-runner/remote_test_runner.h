/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef REMOTE_TEST_RUNNER_H
#define REMOTE_TEST_RUNNER_H

#include <service/test_runner/client/cpp/test_runner_client.h>
#include <service/test_runner/common/test_runner.h>

/*
 * Provides a command line interface for running remote tests.
 */
class remote_test_runner
{
public:
    remote_test_runner();
    remote_test_runner(test_runner_client *client);
    virtual ~remote_test_runner();

    void set_client(test_runner_client *client);

    int execute(int argc, char *argv[]);

private:

    void parse_test_spec_params(int argc, char *argv[], struct test_spec &spec) const;
    std::string parse_option(const char *option_switch, int argc, char *argv[]) const;
    bool option_selected(const char *option_switch, int argc, char *argv[]) const;

    void output_summary(const struct test_summary &summary);
    void output_list(const struct test_summary &summary, const std::vector<struct test_result> &results);
    void output_results(const struct test_summary &summary, const std::vector<struct test_result> &results);

    test_runner_client *m_client;
};

#endif /* REMOTE_TEST_RUNNER_H */
