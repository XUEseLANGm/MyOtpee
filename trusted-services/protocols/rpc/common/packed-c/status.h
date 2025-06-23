/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROTOCOLS_RPC_COMMON_STATUS_H
#define PROTOCOLS_RPC_COMMON_STATUS_H

/* Common RPC status codes for C/C++
 *
 * Alignment of these definitions with other defintions for
 * alternative languages is checked through a set of test cases.
 * These status values are aligned to PSA definitions.
 */
enum
{
	TS_RPC_CALL_ACCEPTED                            =  0,
	TS_RPC_ERROR_EP_DOES_NOT_EXIT                   = -1,
	TS_RPC_ERROR_INVALID_OPCODE                     = -2,
	TS_RPC_ERROR_SERIALIZATION_NOT_SUPPORTED        = -3,
	TS_RPC_ERROR_INVALID_REQ_BODY                   = -4,
	TS_RPC_ERROR_INVALID_RESP_BODY                  = -5,
	TS_RPC_ERROR_RESOURCE_FAILURE                   = -6,
	TS_RPC_ERROR_NOT_READY                          = -7,
	TS_RPC_ERROR_INVALID_TRANSACTION                = -8,
	TS_RPC_ERROR_INTERNAL                           = -9,
	TS_RPC_ERROR_INVALID_PARAMETER                  = -10,
	TS_RPC_ERROR_INTERFACE_DOES_NOT_EXIST           = -11,
	TS_RPC_ERROR_ACCESS_DENIED                      = -12
};

#endif /* PROTOCOLS_RPC_COMMON_STATUS_H */
