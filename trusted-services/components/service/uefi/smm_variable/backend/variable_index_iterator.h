/*
 * Copyright (c) 2021-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef VARIABLE_INDEX_ITERATOR_H
#define VARIABLE_INDEX_ITERATOR_H

#include <stdbool.h>

#include "variable_index.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief An iterator for accessing variable_info
 *
 * Used for iterating over in-use entries held by the associated
 * variable_index.
 */
struct variable_index_iterator {
	const struct variable_index *variable_index;
	size_t current_pos;
};

/**
 * @brief      Initializes an iterator to the first position
 *
 * @param[in]  iter The iterator
 * @param[in]  variable_index The associated variable index
  */
void variable_index_iterator_first(struct variable_index_iterator *iter,
				   const struct variable_index *variable_index);

/**
 * @brief      Check if iterated beyond last entry
 *
 * @param[in]  iter The iterator
 *
 * @return     True if iterating is done
 */
bool variable_index_iterator_is_done(const struct variable_index_iterator *iter);

/**
 * @brief      Return variable info for the current position
 *
 * @param[in]  iter The iterator
 *
 * @return     Pointer to variable_info or NULL
 */
struct variable_info *variable_index_iterator_current(const struct variable_index_iterator *iter);

/**
 * @brief      Iterate to next position
 *
 * @param[in]  iter The iterator
 */
void variable_index_iterator_next(struct variable_index_iterator *iter);

#ifdef __cplusplus
}
#endif

#endif /* VARIABLE_INDEX_ITERATOR_H */
