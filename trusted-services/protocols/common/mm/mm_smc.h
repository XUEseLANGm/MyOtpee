/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MM_SMC_H_
#define MM_SMC_H_

/**
 * The file contains the constant definitions of ARM Magangement Mode Interface
 * specification (DEN0060A) which are used in MM SMC calls.
 */

#include "util.h"

/* MM SMV IDs */
#define ARM_SVC_ID_SP_EVENT_COMPLETE_AARCH32	UINT32_C(0x84000061)
#define ARM_SVC_ID_SP_EVENT_COMPLETE_AARCH64	UINT32_C(0xC4000061)

#ifdef ARM64
#define ARM_SVC_ID_SP_EVENT_COMPLETE ARM_SVC_ID_SP_EVENT_COMPLETE_AARCH64
#else /* ARM64 */
#define ARM_SVC_ID_SP_EVENT_COMPLETE ARM_SVC_ID_SP_EVENT_COMPLETE_AARCH32
#endif /* ARM64 */

/* Return codes */
#define MM_RETURN_CODE_SUCCESS			0
#define MM_RETURN_CODE_NOT_SUPPORTED		-1
#define MM_RETURN_CODE_INVALID_PARAMETER	-2
#define MM_RETURN_CODE_DENIED			-3
/* -4 is skipped according to the spec */
#define MM_RETURN_CODE_NO_MEMORY		-5

#endif /* MM_SMC_H_ */
