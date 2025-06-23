/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_EAT_SIGNER_H
#define PSA_EAT_SIGNER_H

#include <stddef.h>
#include <stdint.h>
#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Sign the serialized EAT token
 *
 * \param[in] key_id         	 Signing key id
 * \param[in] unsigned_token     The token to sign
 * \param[in] unsigned_token_len The token to sign
 * \param[out] signed_token      The signed token
 * \param[out] signed_token_len  The length of the signed token
 *
 * \return Operation status
 */
int eat_sign(psa_key_id_t key_id,
	const uint8_t *unsigned_token, size_t unsigned_token_len,
	const uint8_t **signed_token, size_t *signed_token_len);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PSA_EAT_SIGNER_H */
