/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <psa/crypto.h>

/*
 * The key attributes structure used on the client API doesn't
 * contain an dynamically allocated members so resetting it just
 * requires the structure to be set to its initial value.
 */
void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
	*attributes = psa_key_attributes_init();
}
