/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MAC_SERVICE_SCENARIOS_H
#define MAC_SERVICE_SCENARIOS_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/client/cpp/crypto_client.h>

/*
 * Service-level test scenarios for the mac extension to the crypto service
 * that may be reused using different concrete crypto_clients to check
 * end-to-end operation using different protocol serialization schemes.
 */
class mac_service_scenarios
{
public:
	mac_service_scenarios(crypto_client *crypto_client);
	~mac_service_scenarios();

	void signAndVerify();
	void macAbort();

private:

	psa_status_t generate_key();
	void destroy_key();

	void create_ref_input(size_t size);

	crypto_client *m_crypto_client;
	uint8_t *m_ref_input;
	psa_key_id_t m_keyid;
};

#endif /* MAC_SERVICE_SCENARIOS_H */
