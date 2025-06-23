/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#ifndef OPTEE_SP_INTERNAL_API_H_
#define OPTEE_SP_INTERNAL_API_H_

#include <stdint.h>

/*
 * The file describes the API between the OP-TEE and the SP.
 * The SP code base should also contain a header file named
 * "optee_sp_user_defines.h" for passing the following definitions to the SP dev
 * kit:
 * * OPTEE_SP_UUID: UUID of the SP as an sp_uuid structure
 * * OPTEE_SP_STACK_SIZE: Stack size in bytes
 * * OPTEE_SP_FLAGS: SP attributes (currently none available, set to zero)
 */

/*
 * SP header types
 */
struct optee_sp_uuid {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
};

struct optee_sp_head {
	struct optee_sp_uuid uuid;
	uint32_t stack_size;
	uint32_t flags;
	uint64_t reserved;
};

#endif /* OPTEE_SP_INTERNAL_API_H_ */
