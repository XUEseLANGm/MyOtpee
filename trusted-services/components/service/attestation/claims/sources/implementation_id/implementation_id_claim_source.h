/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef IMPLENTATION_ID_CLAIM_SOURCE_H
#define IMPLENTATION_ID_CLAIM_SOURCE_H

#include <service/attestation/claims/claim_source.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A claim_source that provides an identifier for the
 * root of trust implementation.
 */
struct implementation_id_claim_source
{
	struct claim_source base;
	const char *id_string;
};

/**
 * \brief Initializes a struct implementation_id_claim_source
 *
 * \param[in] instance      The instance to initialze
 * \param[in] id_string		The id string
 *
 * \return The initialize base claim_source structure
 */
struct claim_source *implementation_id_claim_source_init(
	struct implementation_id_claim_source *instance,
	const char *id_string);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* IMPLENTATION_ID_CLAIM_SOURCE_H */
