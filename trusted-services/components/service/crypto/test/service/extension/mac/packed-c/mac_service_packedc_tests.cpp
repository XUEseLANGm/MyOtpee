/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/crypto/client/cpp/protocol/packed-c/packedc_crypto_client.h>
#include <service/crypto/test/service/extension/mac/mac_service_scenarios.h>
#include <protocols/rpc/common/packed-c/encoding.h>
#include <service_locator.h>
#include <CppUTest/TestHarness.h>

/*
 * Service-level mac tests that use the packed-c access protocol serialization
 */
TEST_GROUP(CryptoMacServicePackedcTests)
{
	void setup()
	{
		m_rpc_session = NULL;
		m_crypto_service_context = NULL;
		m_scenarios = NULL;

		service_locator_init();

		m_crypto_service_context = service_locator_query("sn:trustedfirmware.org:crypto:0");
		CHECK_TRUE(m_crypto_service_context);

		m_rpc_session = service_context_open(m_crypto_service_context);
		CHECK_TRUE(m_rpc_session);

		m_scenarios = new mac_service_scenarios(new packedc_crypto_client(m_rpc_session));
	}

	void teardown()
	{
		delete m_scenarios;
		m_scenarios = NULL;

		if (m_crypto_service_context) {
			if (m_rpc_session) {
				service_context_close(m_crypto_service_context, m_rpc_session);
				m_rpc_session = NULL;
			}

			service_context_relinquish(m_crypto_service_context);
			m_crypto_service_context = NULL;
		}
	}

	struct rpc_caller_session *m_rpc_session;
	struct service_context *m_crypto_service_context;
	mac_service_scenarios *m_scenarios;
};

TEST(CryptoMacServicePackedcTests, signAndVerify)
{
	m_scenarios->signAndVerify();
}

TEST(CryptoMacServicePackedcTests, macAbort)
{
	m_scenarios->macAbort();
}