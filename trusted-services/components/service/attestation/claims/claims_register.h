/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CLAIMS_REGISTER_H
#define CLAIMS_REGISTER_H

#include <stdint.h>
#include "claim_vector.h"
#include "claim_source.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The claims_register is a singleton that provides a query
 * method for obtaining claims about a device.  The claims_register
 * decouples a report generator from the details of where claims
 * come from.  A deployment specific set of claim_source objects
 * are registered with the claims_register to actually gather claims.
 */

/**
 * \brief Initialize the singleton claims_register
 *
 */
void claims_register_init(void);

/**
 * \brief De-initializes the claims_register.
 *
 */
void claims_register_deinit(void);

/**
 * \brief Add a claim_source
 *
 * Because of diversity in where information about the security state of
 * a device comes from, a set of deployment specific claim_sources are
 * registered during service provider initialization.  The bitmap
 * of claim categories that can be sourced.
 *
 * \param[in] category_map  The set of claim categries
 * \param[in] source        A concrete claim_source
 */
void claims_register_add_claim_source(uint32_t category_map,
                                struct claim_source *source);

/**
 * \brief Query for claims of a specific category
 *
 * Used by a report generator to obtain claims that correspond to
 * a particular category.
 *
 * \param[in] category  Claim category
 * \param[out] result   Qualifying claims are added to the result claim_vector
 */
void claims_register_query_by_category(enum claim_category category,
                                struct claim_vector *result);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CLAIMS_REGISTER_H */
