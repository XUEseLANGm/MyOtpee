/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LOG_PROTO_H
#define LOG_PROTO_H

#include <stdint.h>

struct __attribute__ ((__packed__)) log_request {
	uint64_t msg_length;
	char msg[];
};

/* Opcodes */
#define TS_LOG_OPCODE_BASE (0x0100)
#define TS_LOG_OPCODE_PUTS (TS_LOG_OPCODE_BASE + 1)

#endif /* LOG_PROTO_H */
