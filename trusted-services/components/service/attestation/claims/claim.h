/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CLAIM_H
#define CLAIM_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct claim;

/**
 * An iterator for accessing claims within a collection.  A concrete
 * claim_iterator provides functions that understand a specific
 * representation of measurements or observations.
 */
struct claim_iterator
{
    /**
     * Initialise the iterator to the first claim
     * in a collection.
     */
    void (*first)(struct claim_iterator *iter);

    /**
     * Advance the iterator to the next claim
     * in a collection.  Returns true if successful.
     */
    bool (*next)(struct claim_iterator *iter);

    /**
     * Check if iterator has reached the end of
     * the collection.
     */
    bool (*is_done)(struct claim_iterator *iter);

    /**
     * Access the claim at the current iterator position.
     * Returns true if there is a valid claim, else false.
     */
    bool (*current)(struct claim_iterator *iter, struct claim *claim);

    /* Abstract handle marking the beginning of a collection */
    const void *begin_pos;

    /* Abstract handle marking the end of a collection */
    const void *end_pos;

    /* Abstract handle marking the current iterator position */
    const void *cur_pos;
};

/**
 * Claim variants for different types of claim.
 */

/* A variant for integer value claims */
struct integer_claim_variant
{
    int32_t value;
};

/* A variant for zero terminated text string claims */
struct text_string_claim_variant
{
    const char *string;
};

/* A variant for byte array claims */
struct byte_string_claim_variant
{
    size_t len;
    const uint8_t *bytes;
};

/* A variant for measurement claims that carry a digest that
 * refects the security state of the mesaured component.
 */
struct measurement_claim_variant
{
    struct text_string_claim_variant id;
    struct byte_string_claim_variant digest;
};

/* A variant that is a container for 0..* claim objects */
struct claim_collection_variant
{
    void (*create_iterator)(const struct claim_collection_variant *variant,
                            struct claim_iterator *iter);

    const void *begin_pos;
    const void *end_pos;
};

/**
 * \brief Initializes an iterator to access a concrete claim collection
 *
 * \param[in] variant    The claim variant to access
 * \param[out] iter      The iterator to initialize
 */
static inline void claim_collection_variant_create_iterator(
                        const struct claim_collection_variant *variant,
                        struct claim_iterator *iter)
{
    variant->create_iterator(variant, iter);
}

/**
 * Claim category.  Values may be combined in a bitmap
 * to allow a set of categries to be expressed.
 */
enum claim_category
{
    CLAIM_CATEGORY_NONE = 0,

    /**
     * A catagory of claim about the device instance.
     */
    CLAIM_CATEGORY_DEVICE = (1U << 0),

    /**
     * A catagory of claim based on a measurement during boot.
     */
    CLAIM_CATEGORY_BOOT_MEASUREMENT = (1U << 1),

    /**
     * A catagory of claim about an associated verifcation service.
     */
    CLAIM_CATEGORY_VERIFICATION_SERVICE = (1U << 2)
};

/**
 * Claim subject identifier.  Used for identifying what the claim relates
 * to.
 */
enum claim_subject_id
{
    CLAIM_SUBJECT_ID_NONE = 0,
    CLAIM_SUBJECT_ID_AUTH_CHALLENGE,
    CLAIM_SUBJECT_ID_INSTANCE_ID,
    CLAIM_SUBJECT_ID_VERIFICATION_SERVICE_INDICATOR,
    CLAIM_SUBJECT_ID_PROFILE_DEFINITION,
    CLAIM_SUBJECT_ID_IMPLEMENTATION_ID,
    CLAIM_SUBJECT_ID_CLIENT_ID,
    CLAIM_SUBJECT_ID_LIFECYCLE_STATE,
    CLAIM_SUBJECT_ID_HW_VERSION,
    CLAIM_SUBJECT_ID_BOOT_SEED,
    CLAIM_SUBJECT_ID_NO_SW_MEASUREMENTS,
    CLAIM_SUBJECT_ID_SW_COMPONENT
};

/**
 * Claim variant identifier.  Identifies the concrete claim variant.
 */
enum claim_variant_id
{
    CLAIM_VARIANT_ID_UNSUPPORTED,
    CLAIM_VARIANT_ID_INTEGER,
    CLAIM_VARIANT_ID_TEXT_STRING,
    CLAIM_VARIANT_ID_BYTE_STRING,
    CLAIM_VARIANT_ID_MEASUREMENT,
    CLAIM_VARIANT_ID_COLLECTION
};

/**
 * The common claim structure, holds a particular variant, identified
 * by the variant_id.  A claim may be an arbitrarily deep tree or just
 * a single node.
 */
struct claim
{
    enum claim_category category;
    enum claim_subject_id subject_id;
    enum claim_variant_id variant_id;

    /* Pointer to the raw record.  Allows a client with
     * knowledge of the record format to access additional
     * information.  NULL if not available.
     */
    const uint8_t *raw_data;

    union claim_variant
    {
        struct integer_claim_variant integer;
        struct text_string_claim_variant text_string;
        struct byte_string_claim_variant byte_string;
        struct measurement_claim_variant measurement;
        struct claim_collection_variant collection;

    } variant;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CLAIM_H */
