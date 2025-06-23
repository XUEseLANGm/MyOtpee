/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <limits.h>
#include <string.h>
#include <service/attestation/client/provision/attest_provision_client.h>
#include <protocols/rpc/common/packed-c/encoding.h>
#include <service_locator.h>
#include <provision/attest_provision.h>
#include <CppUTest/TestHarness.h>

/*
 * Service-level provisioning tests for the attestation service.
 */
TEST_GROUP(AttestationProvisioningTests)
{
    void setup()
    {
        m_rpc_session = NULL;
        m_attest_service_context = NULL;

        service_locator_init();

        m_attest_service_context =
            service_locator_query("sn:trustedfirmware.org:attestation:0");
        CHECK_TRUE(m_attest_service_context);

        m_rpc_session =
            service_context_open(m_attest_service_context);
        CHECK_TRUE(m_rpc_session);

        attest_provision_client_init(m_rpc_session);
    }

    void teardown()
    {
        attest_provision_client_deinit();

	if (m_attest_service_context) {
		if (m_rpc_session) {
			service_context_close(m_attest_service_context, m_rpc_session);
			m_rpc_session = NULL;
		}

		service_context_relinquish(m_attest_service_context);
		m_attest_service_context = NULL;
	}
    }

    struct rpc_caller_session *m_rpc_session;
    struct service_context *m_attest_service_context;
};

/* Reference IAK private key to provision into the key-store.  The public
 * key is generated deterministically from the private key.
 */
static const uint8_t ref_iak_priv_key[] =
{
    0xf1, 0xb7, 0x14, 0x23, 0x43, 0x40, 0x2f, 0x3b, 0x5d, 0xe7, 0x31, 0x5e, 0xa8,
    0x94, 0xf9, 0xda, 0x5c, 0xf5, 0x03, 0xff, 0x79, 0x38, 0xa3, 0x7c, 0xa1, 0x4e,
    0xb0, 0x32, 0x86, 0x98, 0x84, 0x50
};

TEST(AttestationProvisioningTests, selfGeneratedIak)
{
    /* Verify that the provisioning flow where the device self-generates an
     * IAK on first run works as expected.  Because no IAK exists at test entry,
     * the export IAK public key operation should trigger generation of a key.
     */
    psa_status_t status;
    uint8_t iak_pub_key_buf[100];
    size_t iak_pub_key_len = 0;

    status = attest_provision_export_iak_public_key(iak_pub_key_buf,
        sizeof(iak_pub_key_buf), &iak_pub_key_len);

    LONGS_EQUAL(PSA_SUCCESS, status);
    CHECK_TRUE(iak_pub_key_len);

    /* On repeating the export, expect the same initial key value to
     * be returned.
     */
    uint8_t second_iak_pub_key_buf[100];
    size_t second_iak_pub_key_len = 0;

    status = attest_provision_export_iak_public_key(second_iak_pub_key_buf,
        sizeof(second_iak_pub_key_buf), &second_iak_pub_key_len);

    LONGS_EQUAL(PSA_SUCCESS, status);
    UNSIGNED_LONGS_EQUAL(iak_pub_key_len, second_iak_pub_key_len);
    MEMCMP_EQUAL(iak_pub_key_buf, second_iak_pub_key_buf, iak_pub_key_len);

    /* Attempting to import an IAK should be forbidden because one
     * has already been self-generated.
     */
    status = attest_provision_import_iak(ref_iak_priv_key, sizeof(ref_iak_priv_key));

    LONGS_EQUAL(PSA_ERROR_NOT_PERMITTED, status);
}

TEST(AttestationProvisioningTests, provisionedIak)
{
    /* Verify that the provisioning flow where an IAK is generated externally
     * and imported during manufacture.  Note that the initial import is only
     * expected to be successful for a fresh device.
     */
    psa_status_t status = attest_provision_iak_exists();

    if (status == PSA_ERROR_DOES_NOT_EXIST) {

        status = attest_provision_import_iak(ref_iak_priv_key, sizeof(ref_iak_priv_key));
        LONGS_EQUAL(PSA_SUCCESS, status);
    }

    /* Attempting to import again should be forbidden */
    status = attest_provision_import_iak(ref_iak_priv_key, sizeof(ref_iak_priv_key));
    LONGS_EQUAL(PSA_ERROR_NOT_PERMITTED, status);

    /* Check that the IAK public key can be exported */
    uint8_t iak_pub_key_buf[100];
    size_t iak_pub_key_len = 0;

    status = attest_provision_export_iak_public_key(iak_pub_key_buf,
        sizeof(iak_pub_key_buf), &iak_pub_key_len);
    LONGS_EQUAL(PSA_SUCCESS, status);
}
