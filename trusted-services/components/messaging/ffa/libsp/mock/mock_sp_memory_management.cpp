// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include "mock_sp_memory_management.h"

void expect_sp_memory_donate(const struct sp_memory_descriptor *descriptor,
			     const struct sp_memory_access_descriptor *acc_desc,
			     const struct sp_memory_region regions[],
			     uint32_t region_count, const uint64_t *handle,
			     sp_result result)
{
	mock()
		.expectOneCall("sp_memory_donate")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc))
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameterReturning("handle", handle, sizeof(*handle))
		.andReturnValue(result);
}

sp_result sp_memory_donate(struct sp_memory_descriptor *descriptor,
			   struct sp_memory_access_descriptor *acc_desc,
			   struct sp_memory_region regions[],
			   uint32_t region_count, uint64_t *handle)
{
	return mock()
		.actualCall("sp_memory_donate")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc))
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_donate_dynamic(const struct sp_memory_descriptor *descriptor,
				     const struct sp_memory_access_descriptor *acc_desc,
				     const struct sp_memory_region regions[],
				     uint32_t region_count, const uint64_t *handle,
				     sp_result result)
{
	mock()
		.expectOneCall("sp_memory_donate_dynamic")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc))
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameterReturning("handle", handle, sizeof(*handle))
		.andReturnValue(result);
}

sp_result sp_memory_donate_dynamic(struct sp_memory_descriptor *descriptor,
				   struct sp_memory_access_descriptor *acc_desc,
				   struct sp_memory_region regions[],
				   uint32_t region_count, uint64_t *handle,
				   struct ffa_mem_transaction_buffer *buffer)
{
	if (buffer == NULL) { // LCOV_EXCL_BR_LINE
		FAIL("ffa_mem_transaction_buffer is NULL"); // LCOV_EXCL_LINE
	}

	return mock()
		.actualCall("sp_memory_donate_dynamic")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc))
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_donate_dynamic_is_supported(const bool *supported, sp_result result)
{
	mock()
		.expectOneCall("sp_memory_lend_dynamic_is_supported")
		.withOutputParameterReturning("supported", supported, sizeof(*supported))
		.andReturnValue(result);
}

sp_result sp_memory_donate_dynamic_is_supported(bool *supported)
{
	return mock()
		.actualCall("sp_memory_lend_dynamic_is_supported")
		.withOutputParameter("supported", supported)
		.returnIntValue();
}

void expect_sp_memory_lend(const struct sp_memory_descriptor *descriptor,
			   const struct sp_memory_access_descriptor acc_desc[],
			   uint32_t acc_desc_count,
			   const struct sp_memory_region regions[],
			   uint32_t region_count, const uint64_t *handle,
			   sp_result result)
{
	mock()
		.expectOneCall("sp_memory_lend")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameterReturning("handle", handle, sizeof(*handle))
		.andReturnValue(result);
}

sp_result sp_memory_lend(struct sp_memory_descriptor *descriptor,
			 struct sp_memory_access_descriptor acc_desc[],
			 uint32_t acc_desc_count,
			 struct sp_memory_region regions[],
			 uint32_t region_count, uint64_t *handle)
{
	return mock()
		.actualCall("sp_memory_lend")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_lend_dynamic(const struct sp_memory_descriptor *descriptor,
				   const struct sp_memory_access_descriptor acc_desc[],
				   uint32_t acc_desc_count,
				   const struct sp_memory_region regions[],
				   const uint32_t region_count, const uint64_t *handle,
				   sp_result result)
{
	mock()
		.expectOneCall("sp_memory_lend")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameterReturning("handle", handle, sizeof(*handle))
		.andReturnValue(result);
}

sp_result sp_memory_lend_dynamic(struct sp_memory_descriptor *descriptor,
				 struct sp_memory_access_descriptor acc_desc[],
				 uint32_t acc_desc_count,
				 struct sp_memory_region regions[],
				 uint32_t region_count, uint64_t *handle,
				 struct ffa_mem_transaction_buffer *buffer)
{
	if (buffer == NULL) { // LCOV_EXCL_BR_LINE
		FAIL("ffa_mem_transaction_buffer is NULL"); // LCOV_EXCL_LINE
	}

	return mock()
		.actualCall("sp_memory_lend")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_lend_dynamic_is_supported(const bool *supported, sp_result result)
{
	mock()
		.expectOneCall("sp_memory_lend_dynamic_is_supported")
		.withOutputParameterReturning("supported", supported, sizeof(*supported))
		.andReturnValue(result);
}

sp_result sp_memory_lend_dynamic_is_supported(bool *supported)
{
	return mock()
		.actualCall("sp_memory_lend_dynamic_is_supported")
		.withOutputParameter("supported", supported)
		.returnIntValue();
}

void expect_sp_memory_share(const struct sp_memory_descriptor *descriptor,
			    const struct sp_memory_access_descriptor acc_desc[],
			    uint32_t acc_desc_count,
			    const struct sp_memory_region regions[],
			    uint32_t region_count, const uint64_t *handle,
			    sp_result result)
{
	mock()
		.expectOneCall("sp_memory_share")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameterReturning("handle", handle, sizeof(*handle))
		.andReturnValue(result);
}

sp_result sp_memory_share(struct sp_memory_descriptor *descriptor,
			  struct sp_memory_access_descriptor acc_desc[],
			  uint32_t acc_desc_count,
			  struct sp_memory_region regions[],
			  uint32_t region_count, uint64_t *handle)
{
	return mock()
		.actualCall("sp_memory_share")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_share_dynamic(const struct sp_memory_descriptor *descriptor,
				    const struct sp_memory_access_descriptor acc_desc[],
				    uint32_t acc_desc_count,
				    const struct sp_memory_region regions[],
				    uint32_t region_count, const uint64_t *handle,
				    sp_result result)
{
	mock()
		.expectOneCall("sp_memory_share_dynamic")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameterReturning("handle", handle, sizeof(*handle))
		.andReturnValue(result);
}

sp_result sp_memory_share_dynamic(struct sp_memory_descriptor *descriptor,
				  struct sp_memory_access_descriptor acc_desc[],
				  uint32_t acc_desc_count,
				  struct sp_memory_region regions[],
				  uint32_t region_count, uint64_t *handle,
				  struct ffa_mem_transaction_buffer *buffer)
{
	if (buffer == NULL) { // LCOV_EXCL_BR_LINE
		FAIL("ffa_mem_transaction_buffer is NULL"); // LCOV_EXCL_LINE
	}

	return mock()
		.actualCall("sp_memory_share_dynamic")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(*descriptor))
		.withMemoryBufferParameter("acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc) * acc_desc_count)
		.withUnsignedIntParameter("acc_desc_count", acc_desc_count)
		.withMemoryBufferParameter("regions", (const unsigned char *)regions,
					   sizeof(*regions) * region_count)
		.withUnsignedIntParameter("region_count", region_count)
		.withOutputParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_share_dynamic_is_supported(const bool *supported, sp_result result)
{
	mock()
		.expectOneCall("sp_memory_share_dynamic_is_supported")
		.withOutputParameterReturning("supported", supported, sizeof(*supported))
		.andReturnValue(result);
}

sp_result sp_memory_share_dynamic_is_supported(bool *supported)
{
	return mock()
		.actualCall("sp_memory_share_dynamic_is_supported")
		.withOutputParameter("supported", supported)
		.returnIntValue();
}

void expect_sp_memory_retrieve(const struct sp_memory_descriptor *descriptor,
			       const struct sp_memory_access_descriptor *req_acc_desc,
			       const struct sp_memory_access_descriptor *resp_acc_desc,
			       const struct sp_memory_region in_regions[],
			       const struct sp_memory_region out_regions[],
			       uint32_t in_region_count,
			       const uint32_t *out_region_count, uint64_t handle,
			       sp_result result)
{
	mock()
		.expectOneCall("sp_memory_retrieve")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(descriptor))
		.withMemoryBufferParameter("req_acc_desc", (const unsigned char *)req_acc_desc,
					   sizeof(*req_acc_desc))
		.withOutputParameterReturning("resp_acc_desc",
					      (const unsigned char *)resp_acc_desc,
					      sizeof(*resp_acc_desc))
		.withMemoryBufferParameter("in_regions", (const unsigned char *)in_regions,
					   sizeof(*in_regions) * in_region_count)
		.withOutputParameterReturning("out_regions", out_regions,
					      sizeof(*out_regions) * *out_region_count)
		.withUnsignedIntParameter("in_region_count", in_region_count)
		.withOutputParameterReturning("out_region_count", out_region_count,
					      sizeof(*out_region_count))
		.withUnsignedLongIntParameter("handle", handle)
		.andReturnValue(result);

}

sp_result sp_memory_retrieve(struct sp_memory_descriptor *descriptor,
			     struct sp_memory_access_descriptor *acc_desc,
			     struct sp_memory_region regions[],
			     uint32_t in_region_count,
			     uint32_t *out_region_count, uint64_t handle)
{
	return mock()
		.actualCall("sp_memory_retrieve")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(descriptor))
		.withMemoryBufferParameter("req_acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc))
		.withOutputParameter("resp_acc_desc", acc_desc)
		.withMemoryBufferParameter("in_regions", (const unsigned char *)regions,
					   sizeof(*regions) * in_region_count)
		.withOutputParameter("out_regions", regions)
		.withUnsignedIntParameter("in_region_count", in_region_count)
		.withOutputParameter("out_region_count", out_region_count)
		.withUnsignedLongIntParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_retrieve_dynamic(const struct sp_memory_descriptor *descriptor,
				       const struct sp_memory_access_descriptor *req_acc_desc,
				       const struct sp_memory_access_descriptor *resp_acc_desc,
				       const struct sp_memory_region in_regions[],
				       const struct sp_memory_region out_regions[],
				       uint32_t in_region_count,
				       const uint32_t *out_region_count, uint64_t handle,
				       sp_result result)
{
	mock()
		.expectOneCall("sp_memory_retrieve")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(descriptor))
		.withMemoryBufferParameter("req_acc_desc", (const unsigned char *)req_acc_desc,
					   sizeof(*req_acc_desc))
		.withOutputParameterReturning("resp_acc_desc",
					      (const unsigned char *)resp_acc_desc,
					      sizeof(*resp_acc_desc))
		.withMemoryBufferParameter("in_regions", (const unsigned char *)in_regions,
					   sizeof(*in_regions) * in_region_count)
		.withOutputParameterReturning("out_regions", out_regions,
					      sizeof(*out_regions) * *out_region_count)
		.withUnsignedIntParameter("in_region_count", in_region_count)
		.withOutputParameterReturning("out_region_count", out_region_count,
					      sizeof(*out_region_count))
		.withUnsignedLongIntParameter("handle", handle)
		.andReturnValue(result);
}

sp_result
sp_memory_retrieve_dynamic(struct sp_memory_descriptor *descriptor,
			   struct sp_memory_access_descriptor *acc_desc,
			   struct sp_memory_region regions[],
			   uint32_t in_region_count, uint32_t *out_region_count,
			   uint64_t handle,
			   struct ffa_mem_transaction_buffer *buffer)
{
	if (buffer == NULL) { // LCOV_EXCL_BR_LINE
		FAIL("ffa_mem_transaction_buffer is NULL"); // LCOV_EXCL_LINE
	}

	return mock()
		.actualCall("sp_memory_retrieve")
		.withMemoryBufferParameter("descriptor", (const unsigned char *)descriptor,
					   sizeof(descriptor))
		.withMemoryBufferParameter("req_acc_desc", (const unsigned char *)acc_desc,
					   sizeof(*acc_desc))
		.withOutputParameter("resp_acc_desc", acc_desc)
		.withMemoryBufferParameter("in_regions", (const unsigned char *)regions,
					   sizeof(*regions) * in_region_count)
		.withOutputParameter("out_regions", regions)
		.withUnsignedIntParameter("in_region_count", in_region_count)
		.withOutputParameter("out_region_count", out_region_count)
		.withUnsignedLongIntParameter("handle", handle)
		.returnIntValue();
}

void expect_sp_memory_retrieve_dynamic_is_supported(const bool *supported, sp_result result)
{
	mock()
		.expectOneCall("sp_memory_retrieve_dynamic_is_supported")
		.withOutputParameterReturning("supported", supported, sizeof(*supported))
		.andReturnValue(result);
}

sp_result sp_memory_retrieve_dynamic_is_supported(bool *supported)
{
	return mock()
		.actualCall("sp_memory_retrieve_dynamic_is_supported")
		.withOutputParameter("supported", supported)
		.returnIntValue();
}

void expect_sp_memory_relinquish(uint64_t handle, const uint16_t endpoints[],
			         uint32_t endpoint_count,
			         const struct sp_memory_transaction_flags *flags,
				 sp_result result)
{
	mock()
		.expectOneCall("sp_memory_relinquish")
		.withUnsignedLongIntParameter("handle", handle)
		.withMemoryBufferParameter("endpoints", (const unsigned char *)endpoints,
					   sizeof(*endpoints) * endpoint_count)
		.withMemoryBufferParameter("flags", (const unsigned char *)flags, sizeof(*flags))
		.andReturnValue(result);
}

sp_result sp_memory_relinquish(uint64_t handle, const uint16_t endpoints[],
			       uint32_t endpoint_count,
			       struct sp_memory_transaction_flags *flags)
{
	return mock()
		.actualCall("sp_memory_relinquish")
		.withUnsignedLongIntParameter("handle", handle)
		.withMemoryBufferParameter("endpoints", (const unsigned char *)endpoints,
					   sizeof(*endpoints) * endpoint_count)
		.withMemoryBufferParameter("flags", (const unsigned char *)flags, sizeof(*flags))
		.returnIntValue();
}

void expect_sp_memory_reclaim(uint64_t handle, uint32_t flags, sp_result result)
{
	mock()
		.expectOneCall("sp_memory_reclaim")
		.withUnsignedLongIntParameter("handle", handle)
		.withUnsignedIntParameter("flags", flags)
		.andReturnValue(result);
}

sp_result sp_memory_reclaim(uint64_t handle, uint32_t flags)
{
	return mock()
		.actualCall("sp_memory_reclaim")
		.withUnsignedLongIntParameter("handle", handle)
		.withUnsignedIntParameter("flags", flags)
		.returnIntValue();
}

void expect_sp_memory_permission_get(const void *base_address, const struct sp_mem_perm *mem_perm,
				     sp_result result)
{
	mock()
		.expectOneCall("sp_memory_permission_set")
		.withConstPointerParameter("base_address", base_address)
		.withOutputParameterReturning("mem_perm", mem_perm,
					      sizeof(*mem_perm))
		.andReturnValue(result);
}

sp_result sp_memory_permission_get(const void *base_address,
				   struct sp_mem_perm *mem_perm)
{
	return mock()
		.actualCall("sp_memory_permission_set")
		.withConstPointerParameter("base_address", base_address)
		.withOutputParameter("mem_perm", mem_perm)
		.returnIntValue();
}

void expect_sp_memory_permission_set(const void *base_address, size_t region_size,
				     const struct sp_mem_perm *mem_perm, sp_result result)
{
	mock()
		.expectOneCall("sp_memory_permission_set")
		.withConstPointerParameter("base_address", base_address)
		.withUnsignedLongIntParameter("region_size", region_size)
		.withMemoryBufferParameter("mem_perm", (const unsigned char *)mem_perm,
					   sizeof(*mem_perm))
		.andReturnValue(result);
}

sp_result sp_memory_permission_set(const void *base_address, size_t region_size,
				   const struct sp_mem_perm *mem_perm)
{
	return mock()
		.actualCall("sp_memory_permission_set")
		.withConstPointerParameter("base_address", base_address)
		.withUnsignedLongIntParameter("region_size", region_size)
		.withMemoryBufferParameter("mem_perm", (const unsigned char *)mem_perm,
					   sizeof(*mem_perm))
		.returnIntValue();
}
