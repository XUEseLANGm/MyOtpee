/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MM_COMMUNICATE_CARVEOUT_H
#define MM_COMMUNICATE_CARVEOUT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * For compatibility with StMM, MM Communicate messages are passed
 * in a pre-allocated buffer, referred to as the 'carveout'. Because
 * there can only be one of these, the carveout is represented by
 * a singleton that is responsible for one-time setup and teardown,
 * independent of the number of rpc callers.
 */

/**
 * \brief Claim use of the carveout
 *
 * \param[out] buf   	The address of the carveout buffer
 * \param[out] buf_size The size of the buffer
 *
 * \return Status (0 for success)
 */
int carveout_claim(uint8_t **buf, size_t *buf_size);

/**
 * \brief Relinquish use of the carveout
 *
 * \param[in] buf   	The address of the carveout buffer
 * \param[in] buf_size The size of the buffer
 *
 * \return Status (0 for success)
 */
void carveout_relinquish(uint8_t *buf, size_t buf_size);


#ifdef __cplusplus
}
#endif

#endif /* MM_COMMUNICATE_CARVEOUT_H */
