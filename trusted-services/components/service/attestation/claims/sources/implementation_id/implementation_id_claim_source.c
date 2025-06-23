/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <service/attestation/claims/claim.h>
#include "implementation_id_claim_source.h"

static bool get_claim(void *context, struct claim *claim);

struct claim_source *implementation_id_claim_source_init(
	struct implementation_id_claim_source *instance,
	const char *id_string)
{
	instance->base.get_claim = get_claim;
	instance->base.context = instance;

	instance->id_string = id_string;

	return &instance->base;
}

static bool get_claim(void *context, struct claim *claim)
{
	struct implementation_id_claim_source *instance = (struct implementation_id_claim_source*)context;

	if (instance->id_string) {

		claim->category = CLAIM_CATEGORY_DEVICE;
		claim->subject_id = CLAIM_SUBJECT_ID_IMPLEMENTATION_ID;
		claim->variant_id = CLAIM_VARIANT_ID_BYTE_STRING;
		claim->raw_data = NULL;

		claim->variant.byte_string.bytes = (const uint8_t*)instance->id_string;
		claim->variant.byte_string.len = strlen(instance->id_string);
	}

	return instance->id_string;
}
