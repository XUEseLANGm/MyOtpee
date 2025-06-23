// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 */

#include <stdint.h>           // for uint32_t
#include "ffa_api.h"          // for ffa_interrupt_handler
#include "sp_api.h"           // for sp_interrupt_handler

void ffa_interrupt_handler(uint32_t interrupt_id)
{
	sp_interrupt_handler(interrupt_id);
}
