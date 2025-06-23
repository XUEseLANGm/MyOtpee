/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_BACKEND_EMULATED
#define RPMB_BACKEND_EMULATED

#include "../rpmb_backend.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Emulated RPMB backend
 *
 * This backend uses a memory allocated buffer for storing data and it emulates
 * all the necessary data frame checks.
 */
struct rpmb_backend_emulated {
	struct rpmb_backend backend;
	uint8_t *buffer;
	size_t buffer_size;
	uint8_t key[RPMB_KEY_MAC_SIZE];
	bool key_programmed;
	uint32_t write_counter;
	struct rpmb_data_frame result;
};

/**
 * \brief Initialize emulated RPMB backend
 *
 * \param context[in]	Backend context
 * \param size_mult[in]	Size of the RPMB in 128kB units
 * \return struct rpmb_backend*
 */
struct rpmb_backend *rpmb_backend_emulated_init(struct rpmb_backend_emulated *context,
						uint8_t size_mult);

/**
 * \brief Deinitialize emulated RPMB backend
 *
 * \param context[in]	Backend context
 */
void rpmb_backend_emulated_deinit(struct rpmb_backend_emulated *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RPMB_BACKEND_EMULATED */
