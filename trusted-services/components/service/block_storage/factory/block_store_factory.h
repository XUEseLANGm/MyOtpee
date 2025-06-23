/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BLOCK_STORE_FACTORY_H
#define BLOCK_STORE_FACTORY_H

#include <util.h>
#include "service/block_storage/block_store/block_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines a common interface for constructing the block_store
 * stack needed for a deployment. The concrete factory will depend
 * on which factory component has been deployed. This interface
 * is only intended to be used where only one type block store
 * factory is needed in a deployment. This ifdef allows multiple
 * block_store factory methods to be combined within a single build,
 * each with a distinct function name. This is needed for some test
 * deployments where different block_store stacks are constructed
 * for different test cases.
 */
#ifdef CONCRETE_BLOCK_STORE_FACTORY

#define BLOCK_STORE_FACTORY_FUNC_CREATE CONCAT(CONCRETE_BLOCK_STORE_FACTORY, _create)
#define BLOCK_STORE_FACTORY_FUNC_DESTROY CONCAT(CONCRETE_BLOCK_STORE_FACTORY, _destroy)

struct block_store *BLOCK_STORE_FACTORY_FUNC_CREATE(void);
void BLOCK_STORE_FACTORY_FUNC_DESTROY(struct block_store *block_store);

#endif

/**
 * \brief Factory method to create a block_store
 *
 * \return A pointer to the constructed block_store (NULL on failure)
 */
static inline struct block_store *block_store_factory_create(void)
{
#ifdef CONCRETE_BLOCK_STORE_FACTORY
	return BLOCK_STORE_FACTORY_FUNC_CREATE();
#else
	#error No concrete block store factory
#endif
}

/**
 * \brief Destroys a block_store created with block_store_factory_create
 *
 * \param[in] block_store    The block store to destroy
 */
static inline void block_store_factory_destroy(struct block_store *block_store)
{
#ifdef CONCRETE_BLOCK_STORE_FACTORY
	return BLOCK_STORE_FACTORY_FUNC_DESTROY(block_store);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_STORE_FACTORY_H */
