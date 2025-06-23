/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include <CppUTestExt/MockSupport.h>
#include "rpmb_platform_mock.h"

void rpmb_platform_mock_expect_derive_key(void *context, const uint8_t *data, size_t data_length,
					  const uint8_t *key, size_t key_length,
					  psa_status_t result)
{
	mock().expectOneCall("derive_key").
		onObject(context).
		withMemoryBufferParameter("data", data, data_length).
		withOutputParameterReturning("key", key, key_length).
		withUnsignedIntParameter("key_length", key_length).
		andReturnValue(result);
}

static psa_status_t rpmb_platform_derive_key(void *context, const uint8_t *data, size_t data_length,
					     uint8_t *key, size_t key_length)
{
	return mock().actualCall("derive_key").
		onObject(context).
		withMemoryBufferParameter("data", data, data_length).
		withOutputParameter("key", key).
		withUnsignedIntParameter("key_length", key_length).
		returnIntValue();
}

void rpmb_platform_mock_expect_get_nonce(void *context, const uint8_t *nonce, size_t nonce_length,
					 psa_status_t result)
{
	mock().expectOneCall("get_nonce").
		onObject(context).
		withOutputParameterReturning("nonce", nonce, nonce_length).
		withUnsignedIntParameter("nonce_length", nonce_length).
		andReturnValue(result);
}

static psa_status_t rpmb_platform_get_nonce(void *context, uint8_t *nonce, size_t nonce_length)
{
	return mock().actualCall("get_nonce").
		onObject(context).
		withOutputParameter("nonce", nonce).
		withUnsignedIntParameter("nonce_length", nonce_length).
		returnIntValue();
}

void rpmb_platform_mock_expect_calculate_mac(void *context, const uint8_t *key, size_t key_length,
					     const struct rpmb_data_frame *frames,
					     size_t frame_count, const uint8_t *mac,
					     size_t mac_length, psa_status_t result)
{
	mock().expectOneCall("calculate_mac").
		onObject(context).
		withMemoryBufferParameter("key", key, key_length).
		withMemoryBufferParameter("frames", (const unsigned char *)frames, sizeof(*frames) * frame_count).
		withOutputParameterReturning("mac", mac, mac_length).
		withUnsignedIntParameter("mac_length", mac_length).
		andReturnValue(result);
}

static psa_status_t rpmb_platform_calculate_mac(void *context, const uint8_t *key,
						size_t key_length,
						const struct rpmb_data_frame *frames,
						size_t frame_count, uint8_t *mac, size_t mac_length)
{
	return mock().actualCall("calculate_mac").
		onObject(context).
		withMemoryBufferParameter("key", key, key_length).
		withMemoryBufferParameter("frames", (const unsigned char *)frames, sizeof(*frames) * frame_count).
		withOutputParameter("mac", mac).
		withUnsignedIntParameter("mac_length", mac_length).
		returnIntValue();
}

struct rpmb_platform *rpmb_platform_mock_init(struct rpmb_platform_mock *context)
{
	static struct rpmb_platform_interface interface = {
		rpmb_platform_derive_key,
		rpmb_platform_get_nonce,
		rpmb_platform_calculate_mac
	};

	if (!context)
		return NULL;

	context->platform.context = context;
	context->platform.interface = &interface;

	return &context->platform;
}

void rpmb_platform_mock_deinit(struct rpmb_platform_mock *context)
{
	*context = (struct rpmb_platform_mock) { 0 };
}
