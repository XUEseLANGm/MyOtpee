/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SERVICE_INFO_H
#define SERVICE_INFO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Information about a service
 *
 * Provides information to a client about accessing a service provided
 * by a remote service provider instance.
 */
struct service_info
{
	uint32_t supported_encodings;
	size_t max_payload;
};

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_INFO_H */
