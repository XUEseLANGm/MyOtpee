/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "remote_test_runner.h"
#include <protocols/service/test_runner/packed-c/status.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>

remote_test_runner::remote_test_runner() :
    m_client(NULL)
{

}

remote_test_runner::remote_test_runner(test_runner_client *client) :
    m_client(client)
{

}

remote_test_runner::~remote_test_runner()
{

}

void remote_test_runner::set_client(test_runner_client *client)
{
    m_client = client;
}

int remote_test_runner::execute(int argc, char *argv[])
{
    int test_status = TS_TEST_RUNNER_STATUS_ERROR;
    struct test_spec spec;

    /* Parse command line parameters */
    bool list_only = option_selected("-l", argc, argv);
    parse_test_spec_params(argc, argv, spec);

    /* Run or list tests qualified bu spec */
    struct test_summary summary;
    std::vector<struct test_result> results;

    memset(&summary, 0, sizeof(summary));

    test_status = (list_only) ?
        m_client->list_tests(spec, summary, results) :
        m_client->run_tests(spec, summary, results);

    if (test_status == TS_TEST_RUNNER_STATUS_SUCCESS) {

        if (list_only)
            output_list(summary, results);
        else
            output_results(summary, results);
    }
    else {

        printf("Tests failed to run with error: %d\n", test_status);
    }

    return test_status;
}

void remote_test_runner::parse_test_spec_params(int argc, char *argv[], struct test_spec &spec) const
{
    std::string name = parse_option("-n", argc, argv);
    std::string group = parse_option("-g", argc, argv);

    memset(spec.name, 0, TEST_NAME_MAX_LEN);
    name.copy(spec.name, TEST_NAME_MAX_LEN - 1);

    memset(spec.group, 0, TEST_GROUP_MAX_LEN);
    group.copy(spec.group, TEST_GROUP_MAX_LEN - 1);
}

std::string remote_test_runner::parse_option(const char *option_switch, int argc, char *argv[]) const
{
    std::string option;

    for (int i = 1; i + 1 < argc; ++i) {

        if (strcmp(argv[i], option_switch) == 0) {

            option = std::string(argv[i +1]);
            break;
        }
    }

    return option;
}

bool remote_test_runner::option_selected(const char *option_switch, int argc, char *argv[]) const
{
    bool selected = false;

    for (int i = 1; (i < argc) && !selected; ++i) {

        selected = (strcmp(argv[i], option_switch) == 0);
    }

    return selected;
}

void remote_test_runner::output_summary(const struct test_summary &summary)
{
    printf("\n");

    if (summary.num_failed == 0)    printf("OK (");
    else                            printf("Errors (%d failures, ", summary.num_failed);

    printf("%d tests, %d ran)\n", summary.num_tests, summary.num_failed + summary.num_passed);
}


void remote_test_runner::output_list(const struct test_summary &summary,
                                    const std::vector<struct test_result> &results)
{
    for (size_t i = 0; i < results.size(); ++i) {

        printf("TEST(%s, %s)\n", results[i].group, results[i].name);
    }

    output_summary(summary);
}

void remote_test_runner::output_results(const struct test_summary &summary,
                                    const std::vector<struct test_result> &results)
{
    for (size_t i = 0; i < results.size(); ++i) {

        printf("TEST(%s, %s) ", results[i].group, results[i].name);

        if (results[i].run_state == TEST_RUN_STATE_PASSED) {

            printf("OK\n");
        }
        else if (results[i].run_state == TEST_RUN_STATE_FAILED) {

            printf("error\n");
            printf("\tline number: %d\n", results[i].failure.line_num);
            printf("\tinfo: 0x%016lx\n", results[i].failure.info);
        }
        else {

            printf("did not run\n");
        }
    }

    output_summary(summary);
}
