/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2020-2021, Arm Limited. All rights reserved.
 */

#ifndef LIBSP_TEST_MOCK_SP_RXTX_H_
#define LIBSP_TEST_MOCK_SP_RXTX_H_

#include "../include/sp_rxtx.h"

void expect_sp_rxtx_buffer_map(void *tx_buffer, const void *rx_buffer,
			       size_t size, sp_result result);
sp_result sp_rxtx_buffer_map(void *tx_buffer, const void *rx_buffer,
			     size_t size);

void expect_sp_rxtx_buffer_unmap(sp_result result);
sp_result sp_rxtx_buffer_unmap(void);

void expect_sp_rxtx_buffer_alignment_boundary_get(const uintptr_t *alignment,
						  sp_result result);
sp_result sp_rxtx_buffer_alignment_boundary_get(uintptr_t *alignment);

void expect_sp_rxtx_buffer_rx_get(const void **buffer, size_t *size,
				  sp_result sp_result);
sp_result sp_rxtx_buffer_rx_get(const void **buffer, size_t *size);

void expect_sp_rxtx_buffer_tx_get(void **buffer, size_t *size,
				  sp_result result);
sp_result sp_rxtx_buffer_tx_get(void **buffer, size_t *size);

#endif /* LIBSP_TEST_MOCK_SP_RXTX_H_ */
