/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PREFIXED_CRYPTO_API_H
#define PREFIXED_CRYPTO_API_H

/**
 * A set of preprocessor defines that modify psa crypto API function
 * names to avoid name clashes where multiple realizations of the API
 * are included within the same build.
 */
#ifdef BACKEND_CRYPTO_API_ADD_PREFIX

/* Core operations */
#define psa_crypto_init				BACKEND_CRYPTO_API_ADD_PREFIX(psa_crypto_init)
#define psa_asymmetric_decrypt			BACKEND_CRYPTO_API_ADD_PREFIX(psa_asymmetric_decrypt)
#define psa_asymmetric_encrypt			BACKEND_CRYPTO_API_ADD_PREFIX(psa_asymmetric_encrypt)
#define psa_copy_key				BACKEND_CRYPTO_API_ADD_PREFIX(psa_copy_key)
#define psa_destroy_key				BACKEND_CRYPTO_API_ADD_PREFIX(psa_destroy_key)
#define psa_export_key				BACKEND_CRYPTO_API_ADD_PREFIX(psa_export_key)
#define psa_export_public_key			BACKEND_CRYPTO_API_ADD_PREFIX(psa_export_public_key)
#define psa_generate_key			BACKEND_CRYPTO_API_ADD_PREFIX(psa_generate_key)
#define psa_generate_random			BACKEND_CRYPTO_API_ADD_PREFIX(psa_generate_random)
#define psa_get_key_attributes			BACKEND_CRYPTO_API_ADD_PREFIX(psa_get_key_attributes)
#define psa_import_key				BACKEND_CRYPTO_API_ADD_PREFIX(psa_import_key)
#define psa_purge_key				BACKEND_CRYPTO_API_ADD_PREFIX(psa_purge_key)
#define psa_sign_hash				BACKEND_CRYPTO_API_ADD_PREFIX(psa_sign_hash)
#define psa_sign_message			BACKEND_CRYPTO_API_ADD_PREFIX(psa_sign_message)
#define psa_verify_hash				BACKEND_CRYPTO_API_ADD_PREFIX(psa_verify_hash)
#define psa_verify_message			BACKEND_CRYPTO_API_ADD_PREFIX(psa_verify_message)
#define psa_reset_key_attributes		BACKEND_CRYPTO_API_ADD_PREFIX(psa_reset_key_attributes)

/* Cipher operations */
#define psa_cipher_encrypt_setup		BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_encrypt_setup)
#define psa_cipher_decrypt_setup		BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_decrypt_setup)
#define psa_cipher_generate_iv			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_generate_iv)
#define psa_cipher_set_iv			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_set_iv)
#define psa_cipher_update			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_update)
#define psa_cipher_finish			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_finish)
#define psa_cipher_abort			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_abort)
#define psa_cipher_encrypt			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_encrypt)
#define psa_cipher_decrypt			BACKEND_CRYPTO_API_ADD_PREFIX(psa_cipher_decrypt)

/* Hash operations */
#define psa_hash_setup				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_setup)
#define psa_hash_update				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_update)
#define psa_hash_finish				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_finish)
#define psa_hash_abort				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_abort)
#define psa_hash_verify				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_verify)
#define psa_hash_clone				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_clone)
#define psa_hash_suspend			BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_suspend)
#define psa_hash_resume				BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_resume)
#define psa_hash_compare			BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_compare)
#define psa_hash_compute			BACKEND_CRYPTO_API_ADD_PREFIX(psa_hash_compute)

/* Key derivation operations */
#define psa_key_derivation_setup		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_setup)
#define psa_key_derivation_get_capacity		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_get_capacity)
#define psa_key_derivation_set_capacity		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_set_capacity)
#define psa_key_derivation_input_bytes		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_input_bytes)
#define psa_key_derivation_input_key		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_input_key)
#define psa_key_derivation_output_bytes		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_output_bytes)
#define psa_key_derivation_output_key		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_output_key)
#define psa_key_derivation_abort		BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_abort)
#define psa_key_derivation_key_agreement	BACKEND_CRYPTO_API_ADD_PREFIX(psa_key_derivation_key_agreement)
#define psa_raw_key_agreement			BACKEND_CRYPTO_API_ADD_PREFIX(psa_raw_key_agreement)

/* MAC operations */
#define psa_mac_sign_setup			BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_sign_setup)
#define psa_mac_verify_setup			BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_verify_setup)
#define psa_mac_update				BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_update)
#define psa_mac_sign_finish			BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_sign_finish)
#define psa_mac_verify_finish			BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_verify_finish)
#define psa_mac_abort				BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_abort)
#define psa_mac_verify				BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_verify)
#define psa_mac_compute				BACKEND_CRYPTO_API_ADD_PREFIX(psa_mac_compute)

/* AEAD operations */
#define psa_aead_encrypt			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_encrypt)
#define psa_aead_decrypt			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_decrypt)
#define psa_aead_encrypt_setup			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_encrypt_setup)
#define psa_aead_decrypt_setup			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_decrypt_setup)
#define psa_aead_generate_nonce			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_generate_nonce)
#define psa_aead_set_nonce			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_set_nonce)
#define psa_aead_set_lengths			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_set_lengths)
#define psa_aead_update_ad			BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_update_ad)
#define psa_aead_update				BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_update)
#define psa_aead_finish				BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_finish)
#define psa_aead_verify				BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_verify)
#define psa_aead_abort				BACKEND_CRYPTO_API_ADD_PREFIX(psa_aead_abort)

#endif /* BACKEND_CRYPTO_API_ADD_PREFIX */
#endif /* PREFIXED_CRYPTO_API_H */
