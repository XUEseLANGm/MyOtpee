// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#include <compiler.h>
#include "optee_sp_internal_api.h"
#include "optee_sp_user_defines.h"

#ifndef OPTEE_SP_UUID
#error "OPTEE_SP_UUID is not defined in SP"
#endif

#ifndef OPTEE_SP_STACK_SIZE
#error "OPTEE_SP_STACK_SIZE is not defined in SP"
#endif

#ifndef OPTEE_SP_FLAGS
#error "OPTEE_SP_FLAGS is not defined in SP"
#endif

const struct optee_sp_head sp_head __section(".sp_head") = {
	.uuid = OPTEE_SP_UUID,
	.stack_size = OPTEE_SP_STACK_SIZE,
	.flags = OPTEE_SP_FLAGS,
	.reserved = UINT64_MAX
};
