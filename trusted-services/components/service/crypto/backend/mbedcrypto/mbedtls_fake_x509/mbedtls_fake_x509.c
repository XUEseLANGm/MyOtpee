/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../mbedtls_psa_crypto_backend.h"

#include <compiler.h>
#include <stdlib.h>

#include "mbedtls_fake_x509.h"

/*
 * This file contains X509 and PKCS#7 related fake functions. When crypto SP is compiled
 * with a minimalistic mbedtls config which does not support the aformentioned features
 * these functions need to be included to avoid linkage errors.
 */
#if !defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
{
	(void)crt;
}

int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen)
{
	(void)chain;
	(void)buf;
	(void)buflen;

	return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}

void mbedtls_x509_crt_free(mbedtls_x509_crt *crt)
{
	(void)crt;
}
#endif

#if !defined(MBEDTLS_PKCS7_C)
void mbedtls_pkcs7_init(mbedtls_pkcs7 *pkcs7)
{
	(void)pkcs7;
}

int mbedtls_pkcs7_parse_der(mbedtls_pkcs7 *pkcs7, const unsigned char *buf,
                            const size_t buflen)
{
	(void)pkcs7;
	(void)buf;
	(void)buflen;

	return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}

void mbedtls_pkcs7_free(mbedtls_pkcs7 *pkcs7)
{
	(void)pkcs7;
}

int mbedtls_pkcs7_signed_hash_verify(mbedtls_pkcs7 *pkcs7,
		 const mbedtls_x509_crt *cert,
		 const unsigned char *hash, size_t hashlen)
{
	(void)pkcs7;
	(void)cert;
	(void)hash;
	(void)hashlen;

	return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}
#endif
