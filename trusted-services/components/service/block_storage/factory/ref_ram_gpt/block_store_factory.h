/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef REF_RAM_GPT_BLOCK_STORE_FACTORY_H
#define REF_RAM_GPT_BLOCK_STORE_FACTORY_H

#include "service/block_storage/block_store/block_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A block store factory that constructs a partitioned block store with
 * a ram back store. The ram back store is is formatted during construction
 * to contain a GPT that describes the reference set of partitions that
 * many test cases depend on.
 */

/**
 * \brief Factory method to create a block_store
 *
 * \return A pointer to the constructed block_store (NULL on failure)
 */
struct block_store *ref_ram_gpt_block_store_factory_create(void);

/**
 * \brief Destroys a block_store created with block_store_factory_create
 *
 * \param[in] block_store    The block store to destroy
 */
void ref_ram_gpt_block_store_factory_destroy(struct block_store *block_store);

#ifdef __cplusplus
}
#endif

#endif /* REF_RAM_GPT_BLOCK_STORE_FACTORY_H */
