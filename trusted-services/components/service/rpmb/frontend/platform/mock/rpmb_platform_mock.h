/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_PLATFORM_MOCK_H_
#define RPMB_PLATFORM_MOCK_H_

#include "../../rpmb_frontend.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Mock RPMB platform
 *
 * RPMB platform for testing purposes
 */
struct rpmb_platform_mock {
	struct rpmb_platform platform;
};

struct rpmb_platform *rpmb_platform_mock_init(struct rpmb_platform_mock *context);
void rpmb_platform_mock_deinit(struct rpmb_platform_mock *context);

void rpmb_platform_mock_expect_derive_key(void *context, const uint8_t *data, size_t data_length,
					  const uint8_t *key, size_t key_length,
					  psa_status_t result);

void rpmb_platform_mock_expect_get_nonce(void *context, const uint8_t *nonce, size_t nonce_length,
					 psa_status_t result);

void rpmb_platform_mock_expect_calculate_mac(void *context, const uint8_t *key, size_t key_length,
					     const struct rpmb_data_frame *frames,
					     size_t frame_count, const uint8_t *mac,
					     size_t mac_length, psa_status_t result);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_PLATFORM_MOCK_H_ */
