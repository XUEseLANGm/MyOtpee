/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LIBSP_INCLUDE_SP_API_H_
#define LIBSP_INCLUDE_SP_API_H_

#include <stdint.h>    // for uint32_t
#include "compiler.h"  // for __noreturn
#include "ffa_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface for the SP implementation
 */

/**
 * @brief      Interrupt handler of the SP. It is called by the implementation
 *             of ffa_interrupt_handler. SPs must implement this function.
 *
 * @param[in]  interrupt_id  The interrupt identifier
 */
void sp_interrupt_handler(uint32_t interrupt_id);

/**
 * @brief      Entry point of the SP's application code. SPs must implement this
 *             function.
 *
 * @param      boot_info  The boot info
 */
void __noreturn sp_main(union ffa_boot_info *boot_info);

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_INCLUDE_SP_API_H_ */
