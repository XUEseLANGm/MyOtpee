/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MEMORY_REGION_H_
#define MEMORY_REGION_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines a structure for describing a contiguous memory region
 * This may be based on buildtime or runtime configuration information e.g.
 * from device tree.
 */
struct memory_region {
	char region_name[16];   /**< Name of the region e.g. 'mm_comm_buffer' */
	uintptr_t base_addr;    /**< Base address of the region */
	size_t region_size;     /**< Size of memory region in bytes */
};

#ifdef __cplusplus
}
#endif

#endif /* MEMORY_REGION_H_ */
