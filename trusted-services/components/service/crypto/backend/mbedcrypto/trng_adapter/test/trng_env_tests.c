/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <service/test_runner/provider/backend/simple_c/simple_c_test_runner.h>
#include <service/crypto/backend/mbedcrypto/trng_adapter/trng_adapter.h>
#include <string.h>
#include <stddef.h>

/**
 * Tests the hw TRNG provided by the environment or underlying platform.
 */

/* Declaration for mbedtls function to avoid complicated conditional
 * compilation problems in mbedtls header files.
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

/*
 * Check the trng create/destroy lifecycle
 */
static bool check_trng_lifecycle(struct test_failure *failure)
{
    int status = trng_adapter_init(0);
    failure->info = status;
    trng_adapter_deinit();

    return (status == 0);
}

/*
 * Check the trng hardware poll function used by mbedcrypto to
 * access a hardware entropy source,
 */
static bool check_hw_poll(struct test_failure *failure)
{
    bool passed;
    uint8_t output[2][10];
    size_t expected_len = 10;

    passed = (trng_adapter_init(0) == 0);

    memset(output, 0, sizeof(output));

    for (int round = 0; passed && round < 5; ++round) {

        size_t olen;
        int status = mbedtls_hardware_poll(NULL, &output[round & 1][0], expected_len, &olen);

        /* Check results of call - expect a different byte stream on each call */
        passed = passed && (status == 0);
        passed = passed && (olen == expected_len);
        passed = passed && (memcmp(&output[round & 1][0], &output[!(round & 1)][0], expected_len) != 0);

        /* capture most recent output in case of failure */
        memcpy(&failure->info, &output[round & 1][0], sizeof(failure->info));
    }

    trng_adapter_deinit();

    return passed;
}

/**
 * Define an register test group
 */
void trng_env_tests_register(void)
{
    static const struct simple_c_test_case trng_env_tests[] = {
        {.name = "TrngLifecycle", .test_func = check_trng_lifecycle},
        {.name = "TrngHwPoll", .test_func = check_hw_poll}
    };

    static const struct simple_c_test_group trng_env_test_group =
    {
        .group = "TrngEnvTests",
        .num_test_cases = sizeof(trng_env_tests)/sizeof(struct simple_c_test_case),
        .test_cases = trng_env_tests
    };

    simple_c_test_runner_register_group(&trng_env_test_group);
}
