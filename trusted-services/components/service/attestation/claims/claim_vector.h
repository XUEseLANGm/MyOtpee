/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CLAIM_VECTOR_H
#define CLAIM_VECTOR_H

#include <stddef.h>
#include "claim.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A claim_vector is a general purpose variable length array
 * of claims.  The maximum number of claims is specified
 * when the claim_vector is initialized.  Deinit must be
 * called after use to free any allocated space.
 */
struct claim_vector
{
    size_t limit;
    size_t size;
    struct claim *claims;
};

/**
 * \brief Initializes a claim_vector.
 *
 *  Space is allocated for the specified limit but the vector is
 *  initially empty.
 *
 * \param[in] v         This claim_vector
 * \param[in] limit     The maximum number of claims that can be held
 */
void claim_vector_init(struct claim_vector *v, size_t limit);

/**
 * \brief De-initializes a claim_vector.
 *
 *  Frees any space allocated.  Must be called when the claim_vector
 *  is finished with.
 *
 * \param[in] v         This claim_vector
 */
void claim_vector_deinit(struct claim_vector *v);

/**
 * \brief Add a claim to the back of the vector
 *
 * \param[in] v         This claim_vector
 * \param[in] claim     Claim to add to the vector
 */
void claim_vector_push_back(struct claim_vector *v, const struct claim *claim);

/**
 * \brief Returns the number of claims held
 *
 * \param[in] v         This claim_vector
 *
 * \return Count of claims held
 */
size_t claim_vector_size(const struct claim_vector *v);

/**
 * \brief Returns a pointer to the claim at the specified index
 *
 * \param[in] v         This claim_vector
 * \param[in] index     Index into vector
 *
 * \return Pointer to claim or NULL
 */
const struct claim *claim_vector_get_claim(const struct claim_vector *v, size_t index);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CLAIM_VECTOR_H */
