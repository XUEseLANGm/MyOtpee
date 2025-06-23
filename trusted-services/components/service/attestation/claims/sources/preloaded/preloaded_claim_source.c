/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "preloaded_claim_source.h"

static bool preloaded_claim_source_get_claim(void *context, struct claim *claim);
static void create_preloaded_iterator(const struct claim_collection_variant *variant,
                                struct claim_iterator *iter);

static void preloaded_iterator_first(struct claim_iterator *iter);
static bool preloaded_iterator_next(struct claim_iterator *iter);
static bool preloaded_iterator_is_done(struct claim_iterator *iter);
static bool preloaded_iterator_current(struct claim_iterator *iter, struct claim *claim);


struct claim_source *preloaded_claim_source_init(struct preloaded_claim_source *instance,
                                const struct claim_vector *claims)
{
    instance->base.get_claim = preloaded_claim_source_get_claim;
    instance->base.context = instance;

    instance->preloaded_claims = claims;

    return &instance->base;
}

static bool preloaded_claim_source_get_claim(void *context, struct claim *claim)
{
    bool is_available = false;
    struct preloaded_claim_source *instance = (struct preloaded_claim_source*)context;

    /* The claim returned from a preloaded_claim_source is always a claim collection,
     * containing 0..* preloaded claims.
     */
    if (instance->preloaded_claims) {

        claim->subject_id = CLAIM_SUBJECT_ID_NONE;
        claim->variant_id = CLAIM_VARIANT_ID_COLLECTION;
        claim->raw_data = NULL;

        claim->variant.collection.create_iterator = create_preloaded_iterator;
        claim->variant.collection.begin_pos = &instance->preloaded_claims->claims[0];
        claim->variant.collection.end_pos = &instance->preloaded_claims->claims[instance->preloaded_claims->size];

        is_available = true;
    }

    return is_available;
}

static void create_preloaded_iterator(const struct claim_collection_variant *variant,
                                struct claim_iterator *iter)
{
    /* Assign concrete methods */
    iter->first = preloaded_iterator_first;
    iter->next = preloaded_iterator_next;
    iter->is_done = preloaded_iterator_is_done;
    iter->current = preloaded_iterator_current;

    /* Initialize to start of collection */
    iter->begin_pos = variant->begin_pos;
    iter->end_pos = variant->end_pos;
    iter->cur_pos = variant->begin_pos;
}

static void preloaded_iterator_first(struct claim_iterator *iter)
{
    iter->cur_pos = iter->begin_pos;
}

static bool preloaded_iterator_next(struct claim_iterator *iter)
{
    const uint8_t *pos = (const uint8_t*)iter->cur_pos;
    pos += sizeof(struct claim);
    iter->cur_pos = pos;

    return !preloaded_iterator_is_done(iter);
}

static bool preloaded_iterator_is_done(struct claim_iterator *iter)
{
    return (iter->cur_pos >= iter->end_pos) || (iter->cur_pos < iter->begin_pos);
}

static bool preloaded_iterator_current(struct claim_iterator *iter, struct claim *claim)
{
    bool success = false;

    if (!preloaded_iterator_is_done(iter)) {

        const struct claim *current_claim = (const struct claim*)iter->current;
        *claim = *current_claim;
        success = true;
    }

    return success;
}
