// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 */

#include "sp_rxtx.h"
#include "ffa_api.h"
#include <assert.h>
#include <stdlib.h>
#include <stdlib.h>

static void *ffa_tx_buffer;
static const void *ffa_rx_buffer;
static size_t ffa_rxtx_size;

sp_result sp_rxtx_buffer_map(void *tx_buffer, const void *rx_buffer,
			     size_t size)
{
	uintptr_t alignment_mask = 0;
	sp_result sp_res = SP_RESULT_OK;
	ffa_result result = FFA_OK;
	uint32_t page_count = 0;

	/* Checking for invalid parameters*/
	if (!tx_buffer || !rx_buffer || !size)
		return SP_RESULT_INVALID_PARAMETERS;

	/* Checking if the buffers are already mapped */
	if (ffa_rxtx_size)
		return SP_RESULT_INVALID_STATE;

	/* Querying alignment size */
	sp_res = sp_rxtx_buffer_alignment_boundary_get(&alignment_mask);
	if (sp_res != SP_RESULT_OK)
		return sp_res;

	/* Creating a binary mask from the size */
	alignment_mask = alignment_mask - 1;

	/* Checking buffer and size alignment */
	if (((uintptr_t)tx_buffer & alignment_mask) != 0 ||
	    ((uintptr_t)rx_buffer & alignment_mask) != 0 ||
	    (size & alignment_mask) != 0)
		return SP_RESULT_INVALID_PARAMETERS;

	/* Checking max page count for RXTX buffers */
	page_count = size / FFA_RXTX_MAP_PAGE_SIZE;
	if (page_count > FFA_RXTX_MAP_PAGE_COUNT_MAX)
		return SP_RESULT_INVALID_PARAMETERS;

	/* Mapping the buffers */
	result = ffa_rxtx_map(tx_buffer, rx_buffer, page_count);
	if (result != FFA_OK)
		return SP_RESULT_FFA(result);

	/* Storing the buffer pointers and size internally */
	ffa_tx_buffer = tx_buffer;
	ffa_rx_buffer = rx_buffer;
	ffa_rxtx_size = size;

	return SP_RESULT_OK;
}

sp_result sp_rxtx_buffer_unmap(void)
{
	ffa_result result = FFA_OK;
	uint16_t id = 0;

	/* Checking if the buffers are not yet mapped */
	if (!ffa_rxtx_size)
		return SP_RESULT_INVALID_STATE;

	result = ffa_id_get(&id);
	if (result != FFA_OK)
		return SP_RESULT_FFA(result);

	/* Unmapping the buffers */
	result = ffa_rxtx_unmap(id);
	if (result != FFA_OK)
		return SP_RESULT_FFA(result);

	/* Clearing internally stored buffer pointers and size */
	ffa_tx_buffer = NULL;
	ffa_rx_buffer = NULL;
	ffa_rxtx_size = 0;

	return SP_RESULT_OK;
}

sp_result sp_rxtx_buffer_alignment_boundary_get(uintptr_t *alignment)
{
	struct ffa_interface_properties interface_props = { 0 };
	uint32_t *props = NULL;
	ffa_result result = FFA_OK;
	uint32_t granularity = 0;

	/* Checking for invalid parameters */
	if (!alignment)
		return SP_RESULT_INVALID_PARAMETERS;

	/* Querying FFX_RXTX_MAP features */
	result = ffa_features(FFA_RXTX_MAP_64, &interface_props);
	if (result != FFA_OK) {
		*alignment = 0;
		return SP_RESULT_FFA(result);
	}

	props = interface_props.interface_properties;
	granularity = props[FFA_FEATURES_RXTX_MAP_GRANULARITY_INDEX];
	granularity = (granularity >> FFA_FEATURES_RXTX_MAP_GRANULARITY_SHIFT) &
		      FFA_FEATURES_RXTX_MAP_GRANULARITY_MASK;

	switch (granularity) {
	case FFA_FEATURES_RXTX_MAP_GRANULARITY_4K:
		*alignment = 4 * 1024;
		break;

	case FFA_FEATURES_RXTX_MAP_GRANULARITY_64K:
		*alignment = 64 * 1024;
		break;

	case FFA_FEATURES_RXTX_MAP_GRANULARITY_16K:
		*alignment = 16 * 1024;
		break;

	default:
		*alignment = 0;
		return SP_RESULT_INTERNAL_ERROR;
	}

	return SP_RESULT_OK;
}

sp_result sp_rxtx_buffer_rx_get(const void **buffer, size_t *size)
{
	if (!buffer || !size)
		return SP_RESULT_INVALID_PARAMETERS;

	if (!ffa_rxtx_size)
		return SP_RESULT_INVALID_STATE;

	*buffer = ffa_rx_buffer;
	*size = ffa_rxtx_size;

	return SP_RESULT_OK;
}

sp_result sp_rxtx_buffer_tx_get(void **buffer, size_t *size)
{
	if (!buffer || !size)
		return SP_RESULT_INVALID_PARAMETERS;

	if (!ffa_rxtx_size)
		return SP_RESULT_INVALID_STATE;

	*buffer = ffa_tx_buffer;
	*size = ffa_rxtx_size;

	return SP_RESULT_OK;
}
