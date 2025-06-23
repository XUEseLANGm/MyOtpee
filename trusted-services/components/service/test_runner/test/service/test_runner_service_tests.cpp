/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/test_runner/client/cpp/test_runner_client.h>
#include <protocols/rpc/common/packed-c/encoding.h>
#include <protocols/service/test_runner/packed-c/status.h>
#include <service_locator.h>
#include <CppUTest/TestHarness.h>
#include <vector>
#include <cstring>

/*
 * Service-level tests for the test_runner service.  These tests assume
 * that the mock_test_runner backend is used as the only registered
 * backend.  It includes some referenece test cases that are assumed
 * by these tests.
 */
TEST_GROUP(TestRunnerServiceTests)
{
    void setup()
    {
        m_rpc_session = NULL;
        m_test_runner_service_context = NULL;
        m_test_runner_client = NULL;

        service_locator_init();

        m_test_runner_service_context = service_locator_query("sn:trustedfirmware.org:test-runner:0");
        CHECK(m_test_runner_service_context);

        m_rpc_session = service_context_open(m_test_runner_service_context);
        CHECK(m_rpc_session);

        m_test_runner_client = new test_runner_client(m_rpc_session);
    }

    void teardown()
    {
        delete m_test_runner_client;
        m_test_runner_client = NULL;

	if (m_test_runner_service_context) {
	        if (m_rpc_session) {
                        service_context_close(m_test_runner_service_context, m_rpc_session);
                        m_rpc_session = NULL;
	        }

                service_context_relinquish(m_test_runner_service_context);
                m_test_runner_service_context = NULL;
	}
    }

    struct rpc_caller_session *m_rpc_session;
    struct service_context *m_test_runner_service_context;
    test_runner_client *m_test_runner_client;
};

TEST(TestRunnerServiceTests, listAllTests)
{
    int test_status;
    struct test_spec spec;
    struct test_summary summary;
    std::vector<struct test_result> results;

    /* Create spec that qualifies all tests */
    spec.name[0] = 0;
    spec.group[0] = 0;

    test_status = m_test_runner_client->list_tests(spec, summary, results);

    CHECK_EQUAL(TS_TEST_RUNNER_STATUS_SUCCESS, test_status);

    /* Check test summary */
    CHECK_EQUAL(4, summary.num_tests);
    CHECK_EQUAL(4, summary.num_results);
    CHECK_EQUAL(0, summary.num_passed);
    CHECK_EQUAL(0, summary.num_failed);

    /* Check each test result is listed but not run */
    CHECK(strcmp(results[0].group, "PlatformTests") == 0);
    CHECK(strcmp(results[0].name, "Trng") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_NOT_RUN, results[0].run_state);

    CHECK(strcmp(results[1].group, "PlatformTests") == 0);
    CHECK(strcmp(results[1].name, "CheckIOmap") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_NOT_RUN, results[1].run_state);

    CHECK(strcmp(results[2].group, "ConfigTests") == 0);
    CHECK(strcmp(results[2].name, "ValidateConfig") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_NOT_RUN, results[2].run_state);

    CHECK(strcmp(results[3].group, "ConfigTests") == 0);
    CHECK(strcmp(results[3].name, "ApplyConfig") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_NOT_RUN, results[3].run_state);
}

TEST(TestRunnerServiceTests, runAllTests)
{
    int test_status;
    struct test_spec spec;
    struct test_summary summary;
    std::vector<struct test_result> results;

    /* Create spec that qualifies all tests */
    spec.name[0] = 0;
    spec.group[0] = 0;

    test_status = m_test_runner_client->run_tests(spec, summary, results);

    CHECK_EQUAL(TS_TEST_RUNNER_STATUS_SUCCESS, test_status);

    CHECK_EQUAL(4, summary.num_tests);
    CHECK_EQUAL(4, summary.num_results);
    CHECK_EQUAL(3, summary.num_passed);
    CHECK_EQUAL(1, summary.num_failed);

    /* Check each test result has run with the expected outcome */
    CHECK(strcmp(results[0].group, "PlatformTests") == 0);
    CHECK(strcmp(results[0].name, "Trng") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_PASSED, results[0].run_state);

    CHECK(strcmp(results[1].group, "PlatformTests") == 0);
    CHECK(strcmp(results[1].name, "CheckIOmap") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_PASSED, results[1].run_state);

    CHECK(strcmp(results[2].group, "ConfigTests") == 0);
    CHECK(strcmp(results[2].name, "ValidateConfig") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_FAILED, results[2].run_state);
    CHECK_EQUAL(27, results[2].failure.info);

    CHECK(strcmp(results[3].group, "ConfigTests") == 0);
    CHECK(strcmp(results[3].name, "ApplyConfig") == 0);
    CHECK_EQUAL(TEST_RUN_STATE_PASSED, results[3].run_state);
}

TEST(TestRunnerServiceTests, listPlatformTests)
{
    int test_status;
    struct test_spec spec;
    struct test_summary summary;
    std::vector<struct test_result> results;

    /* Create spec that qualifies all tests in a group*/
    spec.name[0] = 0;
    strcpy(spec.group, "PlatformTests");

    test_status = m_test_runner_client->list_tests(spec, summary, results);

    CHECK_EQUAL(TS_TEST_RUNNER_STATUS_SUCCESS, test_status);

    /* Check test summary */
    CHECK_EQUAL(2, summary.num_tests);
    CHECK_EQUAL(2, summary.num_results);
    CHECK_EQUAL(0, summary.num_passed);
    CHECK_EQUAL(0, summary.num_failed);
}

TEST(TestRunnerServiceTests, runConfigTests)
{
    int test_status;
    struct test_spec spec;
    struct test_summary summary;
    std::vector<struct test_result> results;

    /* Create spec that qualifies all tests in a group*/
    spec.name[0] = 0;
    strcpy(spec.group, "ConfigTests");

    test_status = m_test_runner_client->run_tests(spec, summary, results);

    CHECK_EQUAL(TS_TEST_RUNNER_STATUS_SUCCESS, test_status);

    /* Check test summary */
    CHECK_EQUAL(2, summary.num_tests);
    CHECK_EQUAL(2, summary.num_results);
    CHECK_EQUAL(1, summary.num_passed);
    CHECK_EQUAL(1, summary.num_failed);
}

TEST(TestRunnerServiceTests, runSpecificTest)
{
    int test_status;
    struct test_spec spec;
    struct test_summary summary;
    std::vector<struct test_result> results;

    /* Create spec that qualifies a specific test */
    strcpy(spec.name, "ValidateConfig");
    strcpy(spec.group, "ConfigTests");

    test_status = m_test_runner_client->run_tests(spec, summary, results);

    CHECK_EQUAL(TS_TEST_RUNNER_STATUS_SUCCESS, test_status);

    /* Check test summary */
    CHECK_EQUAL(1, summary.num_tests);
    CHECK_EQUAL(1, summary.num_results);
    CHECK_EQUAL(0, summary.num_passed);
    CHECK_EQUAL(1, summary.num_failed);
}
