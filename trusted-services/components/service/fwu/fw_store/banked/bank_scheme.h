/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BANKED_FW_STORE_BANK_SCHEME_H
#define BANKED_FW_STORE_BANK_SCHEME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Definitions for an A/B banked scheme.
 */
#define BANK_SCHEME_NUM_BANKS (2)

/**
 * \brief Returns the index of the next bank to use
 *
 * Given a bank index, returns the index of the next bank to use.
 *
 * \param[in]  bank_index
 *
 * \return Index of next bank to use
 */
static inline uint32_t bank_scheme_next_index(uint32_t bank_index)
{
	return (bank_index == 0) ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* BANKED_FW_STORE_BANK_SCHEME_H */
