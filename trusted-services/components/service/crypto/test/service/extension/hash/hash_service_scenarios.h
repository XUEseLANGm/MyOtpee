/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HASH_SERVICE_SCENARIOS_H
#define HASH_SERVICE_SCENARIOS_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/client/cpp/crypto_client.h>

/*
 * Service-level test scenarios for the hash extension to the crypto service
 * that may be reused using different concrete crypto_clients to check
 * end-to-end operation using different protocol serialization schemes.
 */
class hash_service_scenarios
{
public:
	hash_service_scenarios(crypto_client *crypto_client);
	~hash_service_scenarios();

	void calculateHash();
	void hashAndVerify();
	void hashAbort();

private:

	void create_ref_input(size_t size);

	crypto_client *m_crypto_client;
	uint8_t *m_ref_input;
};

#endif /* HASH_SERVICE_SCENARIOS_H */
