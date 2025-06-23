/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include "claim_vector.h"

void claim_vector_init(struct claim_vector *v, size_t limit)
{
    v->claims = malloc(sizeof(struct claim) * limit);
    v->limit = (v->claims) ? limit : 0;
    v->size = 0;
}

void claim_vector_deinit(struct claim_vector *v)
{
    free(v->claims);
    v->claims = NULL;
    v->limit = 0;
    v->size = 0;
}

void claim_vector_push_back(struct claim_vector *v, const struct claim *claim)
{
    if (v->size < v->limit) {

        v->claims[v->size] = *claim;
        ++v->size;
    }
}

size_t claim_vector_size(const struct claim_vector *v)
{
    return v->size;
}

const struct claim *claim_vector_get_claim(const struct claim_vector *v, size_t index)
{
    const struct claim *claim = NULL;
    if (index < v->size) claim = &v->claims[index];
    return claim;
}
