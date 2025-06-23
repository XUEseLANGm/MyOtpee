/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LIBSP_INCLUDE_FFA_INTERNAL_API_H_
#define LIBSP_INCLUDE_FFA_INTERNAL_API_H_

/**
 * @file  ffa_internal_api.h
 * @brief The file contains the definition of the bottom layer of the SEL-0 FF-A
 *        implementation which SVC caller function.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ARM32
struct ffa_params {
	uint32_t a0;	/**< Function ID */
	uint32_t a1;	/**< Parameter */
	uint32_t a2;	/**< Parameter */
	uint32_t a3;	/**< Parameter */
	uint32_t a4;	/**< Parameter */
	uint32_t a5;	/**< Parameter */
	uint32_t a6;	/**< Parameter */
	uint32_t a7;	/**< Parameter */
};
#endif /* ARM32 */

#ifdef ARM64
struct ffa_params {
	uint64_t a0;	/**< Function ID */
	uint64_t a1;	/**< Parameter */
	uint64_t a2;	/**< Parameter */
	uint64_t a3;	/**< Parameter */
	uint64_t a4;	/**< Parameter */
	uint64_t a5;	/**< Parameter */
	uint64_t a6;	/**< Parameter */
	uint64_t a7;	/**< Parameter */
};
#endif /* ARM64 */

/**
 * @brief      SVC conduit caller function
 * @param[in]  a0, a1, a2, a3, a4, a5, a6, a7 Register values of the request
 * @param[out] result                         Register values of the response
 */
#ifdef ARM64
void ffa_svc(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
	     uint64_t a5, uint64_t a6, uint64_t a7, struct ffa_params *result);
#endif /* ARM64 */

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_INCLUDE_FFA_INTERNAL_API_H_ */
