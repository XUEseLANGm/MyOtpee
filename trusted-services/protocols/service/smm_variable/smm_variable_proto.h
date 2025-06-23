/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_SMM_VARIABLE_PROTO_H
#define TS_SMM_VARIABLE_PROTO_H

#include <protocols/service/smm_variable/opcodes.h>
#include <protocols/service/smm_variable/parameters.h>

/* The GUID used to identify the SMM Variable service */
#define SMM_VARIABLE_GUID \
	{0xed32d533, 0x99e6, 0x4209, { 0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98, 0xa7 }}

#define SMM_VARIABLE_CANONICAL_GUID	"ed32d533-99e6-4209-9cc0-2d72cdd998a7"

#endif /* TS_SMM_VARIABLE_PROTO_H */
