/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ATTEST_REPORT_H
#define ATTEST_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Creates an attestation report
 *
 *  Common interface for creating an attestation report using the
 *  backend reporter incuded in a deployment.
 *
 * \param[in] client_id             The requesting client id
 * \param[in] auth_challenge_data   The auth challenge from the requester
 * \param[in] auth_challenge_len    The auth challenge from the requester
 * \param[out] report               The created report
 * \param[out] report_len           The length of the report
 *
 * \return Operation status
 */
int attest_report_create(int32_t client_id,
        const uint8_t *auth_challenge_data, size_t auth_challenge_len,
        const uint8_t **report, size_t *report_len);

/**
 * \brief Destroys an attestation report
 *
 *  Frees any resource associated with a created report
 *
 * \param[in] report               The created report
 */
void attest_report_destroy(const uint8_t *report);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ATTEST_REPORT_H */
