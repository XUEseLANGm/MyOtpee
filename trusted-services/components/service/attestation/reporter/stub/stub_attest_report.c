/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * A stub attestation reporter that doesn't do anything apart from
 * return failure whne requested to create a report.  Intended to
 * be used when creating a new deployment to temporarily satisfy
 * attestation service provider dependencies on a reporter.
 */

#include <stddef.h>
#include <psa/error.h>
#include <service/attestation/reporter/attest_report.h>

int attest_report_create(int32_t client_id,
    const uint8_t *auth_challenge_data, size_t auth_challenge_len,
    const uint8_t **report, size_t *report_len)
{
    (void)client_id;
    (void)auth_challenge_data;
    (void)auth_challenge_len;

    *report = NULL;
    *report_len = 0;

    return PSA_ERROR_NOT_SUPPORTED;
}

void attest_report_destroy(const uint8_t *report)
{
    (void)report;
}
