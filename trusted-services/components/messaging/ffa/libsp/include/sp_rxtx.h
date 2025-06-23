/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LIBSP_INCLUDE_SP_RXTX_H_
#define LIBSP_INCLUDE_SP_RXTX_H_

/**
 * @file  sp_rxtx.h
 * @brief The functions of this file provide a higher API for the FF-A RXTX
 *        buffer handling.
 */

#include "sp_api_defines.h"
#include "sp_api_types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Maps the RX/TX buffer pair in the callee's translation regime.
 *
 * @param[in]  tx_buffer  The transmit buffer
 * @param[in]  rx_buffer  The receive buffer
 * @param[in]  size       The buffer size
 *
 * @return     The SP API result
 */
sp_result sp_rxtx_buffer_map(void *tx_buffer, const void *rx_buffer,
			     size_t size);

/**
 * @brief      Unmaps the RX/TX buffer pair in the callee's translation regime.
 *
 * @return     The SP API result
 */
sp_result sp_rxtx_buffer_unmap(void);

/**
 * @brief      Queries the required alignment boundary of the RXTX buffers.
 *
 * @param[out] alignment  The minimal buffer size and alignment boundary
 *
 * @return     The SP API result
 */
sp_result sp_rxtx_buffer_alignment_boundary_get(uintptr_t *alignment);

/**
 * @brief      Queries the RX buffer's address and size.
 *
 * @param[out] buffer  The buffer address
 * @param[out] size    The buffer size
 *
 * @return     The SP API result
 */
sp_result sp_rxtx_buffer_rx_get(const void **buffer, size_t *size);

/**
 * @brief      Queries the TX buffer's address and size.
 *
 * @param      buffer  The buffer address
 * @param      size    The buffer size
 *
 * @return     The SP API result
 */
sp_result sp_rxtx_buffer_tx_get(void **buffer, size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_INCLUDE_SP_RXTX_H_ */
