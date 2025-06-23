/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <psa/error.h>
#include <service/attestation/key_mngr/attest_key_mngr.h>

psa_status_t attest_key_mngr_get_iak_id(
	psa_key_id_t *iak_id)
{
	(void)iak_id;

	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t attest_key_mngr_export_iak_public_key(
	uint8_t *data, size_t data_size, size_t *data_length)
{
	(void)data;
	(void)data_size;
	(void)data_length;

	return PSA_ERROR_NOT_SUPPORTED;
}

size_t attest_key_mngr_max_iak_export_size(void)
{
	return 0;
}

size_t attest_key_mngr_max_iak_import_size(void)
{
	return 0;
 }

psa_status_t attest_key_mngr_import_iak(
	const uint8_t *data, size_t data_length)
{
	(void)data;
	(void)data_length;

	return PSA_ERROR_NOT_SUPPORTED;
}

bool attest_key_mngr_iak_exists(void)
{
	return false;
}
