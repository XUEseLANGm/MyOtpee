/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>
#include <psa/crypto.h>
#include <service/attestation/key_mngr/attest_key_mngr.h>
#include "local_attest_key_mngr.h"

/**
 * The singleton local_attest_key_mngr instance.
 */
static struct local_attest_key_mngr
{
	psa_key_id_t cfg_iak_id;	/* The configured IAK key id (zero for volatile) */
	psa_key_id_t iak_id;		/* The actual IAK key id */
} instance;

/* Local defines */
#define IAK_KEY_BITS        (256)

/**
 * \brief Set the IAK key attributes
 *
 * \param[out] attribute   Key attributes object to set
 * \param[in] cfg_iak_id   The configured IAK key id or zero for volatile key
 */
static void set_iak_attributes(psa_key_attributes_t *attributes, psa_key_id_t cfg_iak_id)
{
	if (cfg_iak_id)
		psa_set_key_id(attributes, cfg_iak_id);
	else
		psa_set_key_lifetime(attributes, PSA_KEY_LIFETIME_VOLATILE);

	psa_set_key_usage_flags(attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);

	psa_set_key_algorithm(attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(attributes, IAK_KEY_BITS);
}

/**
 * \brief Generates the IAK
 *
 *  If an IAK hasn't been provisioned during manufacture, there is the
 *  option to generate a persistent IAK on first run.
 *
 * \param[in] cfg_iak_id   	The configured IAK key id or zero for volatile key
 * \param[out] iak_id  		The returned IAK key id
 *
 * \return Status
 */
static psa_status_t generate_iak(psa_key_id_t cfg_iak_id, psa_key_id_t *iak_id)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	set_iak_attributes(&attributes, cfg_iak_id);
	status = psa_generate_key(&attributes, iak_id);

	psa_reset_key_attributes(&attributes);

	return status;
}

void local_attest_key_mngr_init(psa_key_id_t cfg_iak_id)
{
	instance.cfg_iak_id = cfg_iak_id;
	instance.iak_id = 0;
}

void local_attest_key_mngr_deinit(void)
{
	if (!instance.cfg_iak_id && instance.iak_id) {

		/* Clean-up if IAK is volatile */
		psa_destroy_key(instance.iak_id);
		instance.iak_id = 0;
	}
}

psa_status_t attest_key_mngr_get_iak_id(psa_key_id_t *iak_id)
{
	psa_status_t status = PSA_SUCCESS;

	if (!instance.iak_id) {

		if (instance.cfg_iak_id) {

			/* A valid key id has been configured so treat as a persistent key
			 * that will normally already exist.
			 */
			psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
			status = psa_get_key_attributes(instance.cfg_iak_id, &attributes);

			if (status == PSA_SUCCESS) {

				/* A persistent key has already been provisioned */
				instance.iak_id = psa_get_key_id(&attributes);
			}
			else {

				/* First run and no key has been provisioned */
				status = generate_iak(instance.iak_id, &instance.iak_id);
			}

			psa_reset_key_attributes(&attributes);
		}
		else {

			/* An invalid key id has been specified which indicates that a
			 * volatile key should be generated.  This is option is intended
			 * for test purposes only.
			 */
			status = generate_iak(instance.cfg_iak_id, &instance.iak_id);
		}
	}

	*iak_id = instance.iak_id;
	return status;
}

psa_status_t attest_key_mngr_export_iak_public_key(
	uint8_t *data, size_t data_size, size_t *data_length)
{
	psa_key_id_t id;
	psa_status_t status = attest_key_mngr_get_iak_id(&id);

	if (status == PSA_SUCCESS) {

		status = psa_export_public_key(id, data, data_size, data_length);
	}

	return status;
}

size_t attest_key_mngr_max_iak_export_size(void)
{
	return PSA_EXPORT_KEY_OUTPUT_SIZE(
		PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)),
			IAK_KEY_BITS);
}

size_t attest_key_mngr_max_iak_import_size(void)
{
	return PSA_BITS_TO_BYTES(IAK_KEY_BITS);
 }

psa_status_t attest_key_mngr_import_iak(const uint8_t *data, size_t data_length)
{
	psa_status_t status = PSA_ERROR_NOT_PERMITTED;

	if (!instance.iak_id) {

		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		set_iak_attributes(&attributes, instance.cfg_iak_id);

		status = psa_import_key(&attributes, data, data_length, &instance.iak_id);

		psa_reset_key_attributes(&attributes);
	}

	return status;
}

bool attest_key_mngr_iak_exists(void)
{
	bool exists = false;

	psa_key_id_t key_id = (instance.iak_id) ? instance.iak_id : instance.cfg_iak_id;

	if (key_id) {

		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_status_t status = psa_get_key_attributes(key_id, &attributes);
		psa_reset_key_attributes(&attributes);

		exists = (status == PSA_SUCCESS);
	}

	return exists;
}
