/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_H
#define TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_H

#include <stdint.h>

/* Variable length input parameter tags */
enum {
	TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_IN_TAG_SIGNATURE = 1,
	TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_IN_TAG_HASH = 2,
	TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_IN_TAG_PUBLIC_KEY_CERT = 3
};

#endif /* TS_CRYPTO_VERIFY_PKCS7_SIGNATURE_H */
