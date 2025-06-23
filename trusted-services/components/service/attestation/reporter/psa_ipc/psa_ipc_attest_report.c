/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * A attestation reporter for psa ipc
 */

#include <stddef.h>
#include <psa/error.h>
#include <service/attestation/reporter/attest_report.h>
#include <psa/initial_attestation.h>

#define TOKEN_BUF_SIZE	1024

static uint8_t token_buf[TOKEN_BUF_SIZE];

int attest_report_create(int32_t client_id, const uint8_t *auth_challenge_data,
			 size_t auth_challenge_len, const uint8_t **report,
			 size_t *report_len)
{
	*report = token_buf;
	psa_status_t ret;
	size_t token_size = 0;

	ret = psa_initial_attest_get_token(auth_challenge_data,
					   auth_challenge_len, token_buf,
					   TOKEN_BUF_SIZE, &token_size);
	if (ret != PSA_SUCCESS) {
		*report = NULL;
		*report_len = 0;
		return ret;
	}

	*report_len = token_size;

	return PSA_SUCCESS;
}

void attest_report_destroy(const uint8_t *report)
{
	(void)report;
}
