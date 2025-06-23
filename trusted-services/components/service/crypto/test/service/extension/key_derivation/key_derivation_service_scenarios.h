/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef KEY_DERIVATION_SERVICE_SCENARIOS_H
#define KEY_DERIVATION_SERVICE_SCENARIOS_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/client/cpp/crypto_client.h>

/*
 * Service-level test scenarios for the key_derivation extension to the
 * crypto service that may be reused using different concrete
 * crypto_clients to check end-to-end operation using different protocol
 * serialization schemes.
 */
class key_derivation_service_scenarios
{
public:
	key_derivation_service_scenarios(crypto_client *crypto_client);
	~key_derivation_service_scenarios();

	void hkdfDeriveKey();
	void hkdfDeriveBytes();
	void deriveAbort();

private:

	psa_status_t generateSecretKey();
	void destroySecretKey();

	crypto_client *m_crypto_client;
	psa_key_id_t m_secret_keyid;
};

#endif /* KEY_DERIVATION_SERVICE_SCENARIOS_H */
