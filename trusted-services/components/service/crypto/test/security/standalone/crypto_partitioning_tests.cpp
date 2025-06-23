/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/crypto/client/cpp/protocol/packed-c/packedc_crypto_client.h>
#include <service/locator/interface/service_locator.h>
#include <CppUTest/TestHarness.h>

/*
 * Security tests to check key store partition protects access to keys
 */
TEST_GROUP(CryptoSecurityPartitioningTests)
{
	void setup()
	{
		m_crypto_service_context = NULL;
		m_rpc_session_a = NULL;
		m_rpc_session_b = NULL;
		m_client_a = NULL;
		m_client_b = NULL;

		service_locator_init();

		m_crypto_service_context = service_locator_query("sn:trustedfirmware.org:crypto:0");
		CHECK_TRUE(m_crypto_service_context);

		/*
		 * Open two RPC sessions, one for client a and the other for client b.
		 * Both have different client identities, assigned when the rpc session is opened.
		 */
		m_rpc_session_a = service_context_open(m_crypto_service_context);
		CHECK_TRUE(m_rpc_session_a);
		m_client_a = new packedc_crypto_client(m_rpc_session_a);

		m_rpc_session_b = service_context_open(m_crypto_service_context);
		CHECK_TRUE(m_rpc_session_b);
		m_client_b = new packedc_crypto_client(m_rpc_session_b);
	}

	void teardown()
	{
		delete m_client_a;
		m_client_a = NULL;

		delete m_client_b;
		m_client_b = NULL;

		if (m_crypto_service_context) {
			if (m_rpc_session_a) {
				service_context_close(m_crypto_service_context, m_rpc_session_a);
				m_rpc_session_a = NULL;
			}

			if (m_rpc_session_b) {
				service_context_close(m_crypto_service_context, m_rpc_session_b);
				m_rpc_session_b = NULL;
			}

			service_context_relinquish(m_crypto_service_context);
			m_crypto_service_context = NULL;
		}
	}

	struct service_context *m_crypto_service_context;
	struct rpc_caller_session *m_rpc_session_a;
	struct rpc_caller_session *m_rpc_session_b;
	crypto_client *m_client_a;
	crypto_client *m_client_b;
};

TEST(CryptoSecurityPartitioningTests, unauthorizedKeyDestroy)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);

	/* Generate a key in the context of client a */
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	status = m_client_a->generate_key(&attributes, &key_id);
	CHECK_EQUAL(PSA_SUCCESS, status);

	/* Client b attempts to destroy it but shouldn't be permitted */
	status = m_client_b->destroy_key(key_id);
	CHECK_EQUAL(PSA_ERROR_INVALID_HANDLE, status);

	/* Client a should be permitted */
	status = m_client_a->destroy_key(key_id);
	CHECK_EQUAL(PSA_SUCCESS, status);

	psa_reset_key_attributes(&attributes);
}

TEST(CryptoSecurityPartitioningTests, independentKeyIdSpace)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);

	/*
	 * Use the same key id from both clients.  Expect clients to have
	 * independent key id spaces.
	 */
	psa_key_id_t common_key_id = 1111;

	/* Client A generates key */
	psa_key_id_t key_id_a = PSA_KEY_ID_NULL;
	psa_set_key_id(&attributes, common_key_id);
	status = m_client_a->generate_key(&attributes, &key_id_a);
	CHECK_EQUAL(PSA_SUCCESS, status);
	CHECK_EQUAL(common_key_id, key_id_a);

	/* Client B does the same using the same key_id */
	psa_key_id_t key_id_b = PSA_KEY_ID_NULL;
	psa_set_key_id(&attributes, common_key_id);
	status = m_client_b->generate_key(&attributes, &key_id_b);
	CHECK_EQUAL(PSA_SUCCESS, status);
	CHECK_EQUAL(common_key_id, key_id_b);

	/* Expect both clients to have access to their own keys */
	status = m_client_a->destroy_key(key_id_a);
	CHECK_EQUAL(PSA_SUCCESS, status);
	status = m_client_b->destroy_key(key_id_b);
	CHECK_EQUAL(PSA_SUCCESS, status);

	psa_reset_key_attributes(&attributes);
}
