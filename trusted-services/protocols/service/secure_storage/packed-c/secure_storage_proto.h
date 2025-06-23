/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SECURE_STORAGE_PROTO_H
#define SECURE_STORAGE_PROTO_H

#include <stdint.h>

/* Operation SET request parameters */
struct __attribute__ ((__packed__)) secure_storage_request_set {
	uint64_t uid;
	uint64_t data_length;
	uint32_t create_flags;
	uint8_t p_data[];
};

/* Operation GET request parameters */
struct __attribute__ ((__packed__)) secure_storage_request_get {
	uint64_t uid;
	uint64_t data_offset;
	uint64_t data_size;
};

/* Operation GET_INFO request and response parameters */
struct __attribute__ ((__packed__)) secure_storage_request_get_info {
	uint64_t uid;
};

struct __attribute__ ((__packed__)) secure_storage_response_get_info {
	uint64_t capacity;
	uint64_t size;
	uint32_t flags;
};

/* Operation REMOVE request parameters */
struct __attribute__ ((__packed__)) secure_storage_request_remove {
	uint64_t uid;
};

/* Operation CREATE request parameters */
struct __attribute__ ((__packed__)) secure_storage_request_create {
	uint64_t uid;
	uint64_t capacity;
	uint32_t create_flags;
};

/* Operation SET_EXTENDED request parameters */
struct __attribute__ ((__packed__)) secure_storage_request_set_extended {
	uint64_t uid;
	uint64_t data_offset;
	uint64_t data_length;
	uint8_t p_data[];
};

/* Operation GET_SUPPORT response parameters */
struct __attribute__ ((__packed__)) secure_storage_response_get_support {
	uint32_t support;
};

#define TS_SECURE_STORAGE_OPCODE_BASE			(0x100u)

#define TS_SECURE_STORAGE_OPCODE_SET			(TS_SECURE_STORAGE_OPCODE_BASE + 0u)
#define TS_SECURE_STORAGE_OPCODE_GET			(TS_SECURE_STORAGE_OPCODE_BASE + 1u)
#define TS_SECURE_STORAGE_OPCODE_GET_INFO		(TS_SECURE_STORAGE_OPCODE_BASE + 2u)
#define TS_SECURE_STORAGE_OPCODE_REMOVE			(TS_SECURE_STORAGE_OPCODE_BASE + 3u)
#define TS_SECURE_STORAGE_OPCODE_CREATE			(TS_SECURE_STORAGE_OPCODE_BASE + 4u)
#define TS_SECURE_STORAGE_OPCODE_SET_EXTENDED	(TS_SECURE_STORAGE_OPCODE_BASE + 5u)
#define TS_SECURE_STORAGE_OPCODE_GET_SUPPORT	(TS_SECURE_STORAGE_OPCODE_BASE + 6u)

#define TS_SECURE_STORAGE_FLAG_NONE			(0u)
#define TS_SECURE_STORAGE_FLAG_WRITE_ONCE		(1u << 0)
#define TS_SECURE_STORAGE_FLAG_NO_CONFIDENTIALITY	(1u << 1)
#define TS_SECURE_STORAGE_FLAG_NO_REPLAY_PROTECTION	(1u << 2)
#define TS_SECURE_STORAGE_SUPPORT_SET_EXTENDED		(1u << 0)

#endif /* SECURE_STORAGE_PROTO_H */
