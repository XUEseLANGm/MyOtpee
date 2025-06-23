/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CRYPTO_CALLER_SELECTOR_H
#define CRYPTO_CALLER_SELECTOR_H

/**
 * This header file selects which crypto caller is used as a backend
 * for the psa crypto API client.  Selection is made at build-time to
 * allow psa crypto API operations to be handled by alternative backend
 * crypto callers to meet the needs of a deployment.
 */

/* Set the default if no deployment specific selection has been made */
#ifndef PSA_CRYPTO_CLIENT_CALLER_SELECTION_H
#define PSA_CRYPTO_CLIENT_CALLER_SELECTION_H "service/crypto/client/caller/packed-c/crypto_caller.h"
#endif

/* Include the selected crypto caller interface header file */
#include PSA_CRYPTO_CLIENT_CALLER_SELECTION_H

#endif /* CRYPTO_CALLER_SELECTOR_H */
