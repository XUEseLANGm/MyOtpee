/*
 * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PSA_STORAGE_COMMON_H
#define PSA_STORAGE_COMMON_H

#include <psa/error.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Types */
typedef uint64_t psa_storage_uid_t;
typedef uint32_t psa_storage_create_flags_t;

struct psa_storage_info_t {
	uint32_t capacity;
	uint32_t size;
	psa_storage_create_flags_t flags;
};

/* Storage flags */
#define PSA_STORAGE_FLAG_NONE			(0u)
#define PSA_STORAGE_FLAG_WRITE_ONCE		(1u << 0)
#define PSA_STORAGE_FLAG_NO_CONFIDENTIALITY	(1u << 1)
#define PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION	(1u << 2)
#define PSA_STORAGE_SUPPORT_SET_EXTENDED	(1u << 0)

/* Status codes */
#define PSA_ERROR_INVALID_SIGNATURE		((psa_status_t)-149)
#define PSA_ERROR_DATA_CORRUPT			((psa_status_t)-152)

#ifdef __cplusplus
}
#endif

#endif /* PSA_STORAGE_COMMON_H */
