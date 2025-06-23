/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_BLOB_H
#define CONFIG_BLOB_H

#include <stddef.h>

/**
 * A general-purpose blob of configuarion data.  Points to a buffer
 * that contains the actual data.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Structure definition for a config_blob
 *
 */
struct config_blob
{
	const void *data;
	size_t data_len;
};

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_BLOB_H */
