/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LIBSP_MOCK_MOCK_SP_MEMORY_MANAGEMENT_H_
#define LIBSP_MOCK_MOCK_SP_MEMORY_MANAGEMENT_H_

#include "../include/sp_memory_management.h"

#ifdef __cplusplus
extern "C" {
#endif

void expect_sp_memory_donate(const struct sp_memory_descriptor *descriptor,
			     const struct sp_memory_access_descriptor *acc_desc,
			     const struct sp_memory_region regions[],
			     uint32_t region_count, const uint64_t *handle,
			     sp_result result);

void expect_sp_memory_donate_dynamic(const struct sp_memory_descriptor *descriptor,
				     const struct sp_memory_access_descriptor *acc_desc,
				     const struct sp_memory_region regions[],
				     uint32_t region_count, const uint64_t *handle,
				     sp_result result);

void expect_sp_memory_donate_dynamic_is_supported(const bool *supported, sp_result result);

void expect_sp_memory_lend(const struct sp_memory_descriptor *descriptor,
			   const struct sp_memory_access_descriptor acc_desc[],
			   uint32_t acc_desc_count,
			   const struct sp_memory_region regions[],
			   uint32_t region_count, const uint64_t *handle,
			   sp_result result);

void expect_sp_memory_lend_dynamic(const struct sp_memory_descriptor *descriptor,
				   const struct sp_memory_access_descriptor acc_desc[],
				   uint32_t acc_desc_count,
				   const struct sp_memory_region regions[],
				   const uint32_t region_count, const uint64_t *handle,
				   sp_result result);

void expect_sp_memory_lend_dynamic_is_supported(const bool *supported, sp_result result);

void expect_sp_memory_share(const struct sp_memory_descriptor *descriptor,
			    const struct sp_memory_access_descriptor acc_desc[],
			    uint32_t acc_desc_count,
			    const struct sp_memory_region regions[],
			    uint32_t region_count, const uint64_t *handle,
			    sp_result result);

void expect_sp_memory_share_dynamic(const struct sp_memory_descriptor *descriptor,
				    const struct sp_memory_access_descriptor acc_desc[],
				    uint32_t acc_desc_count,
				    const struct sp_memory_region regions[],
				    uint32_t region_count, const uint64_t *handle,
				    sp_result result);

void expect_sp_memory_share_dynamic_is_supported(const bool *supported, sp_result result);

void expect_sp_memory_retrieve(const struct sp_memory_descriptor *descriptor,
			       const struct sp_memory_access_descriptor *req_acc_desc,
			       const struct sp_memory_access_descriptor *resp_acc_desc,
			       const struct sp_memory_region in_regions[],
			       const struct sp_memory_region out_regions[],
			       uint32_t in_region_count,
			       const uint32_t *out_region_count, uint64_t handle,
			       sp_result result);

void expect_sp_memory_retrieve_dynamic(const struct sp_memory_descriptor *descriptor,
				       const struct sp_memory_access_descriptor *req_acc_desc,
				       const struct sp_memory_access_descriptor *resp_acc_desc,
				       const struct sp_memory_region in_regions[],
				       const struct sp_memory_region out_regions[],
				       uint32_t in_region_count,
				       const uint32_t *out_region_count, uint64_t handle,
				       sp_result result);

void expect_sp_memory_retrieve_dynamic_is_supported(const bool *supported, sp_result result);

void expect_sp_memory_relinquish(uint64_t handle, const uint16_t endpoints[],
				 uint32_t endpoint_count,
				 const struct sp_memory_transaction_flags *flags,
				 sp_result result);

void expect_sp_memory_reclaim(uint64_t handle, uint32_t flags, sp_result result);

void expect_sp_memory_permission_get(const void *base_address, const struct sp_mem_perm *mem_perm,
				     sp_result result);

void expect_sp_memory_permission_set(const void *base_address, size_t region_size,
				     const struct sp_mem_perm *mem_perm, sp_result result);

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_MOCK_MOCK_SP_MEMORY_MANAGEMENT_H_ */
