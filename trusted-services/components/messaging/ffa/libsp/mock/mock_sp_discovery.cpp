// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 */

#include <CppUTestExt/MockSupport.h>
#include "mock_sp_discovery.h"

void expect_sp_discovery_ffa_version_get(const uint16_t *major,
					 const uint16_t *minor,
					 sp_result result)
{
	mock()
		.expectOneCall("sp_discovery_ffa_version_get")
		.withOutputParameterReturning("major", major, sizeof(*major))
		.withOutputParameterReturning("minor", minor, sizeof(*minor))
		.andReturnValue(result);
}

sp_result sp_discovery_ffa_version_get(uint16_t *major, uint16_t *minor)
{
	return mock()
		.actualCall("sp_discovery_ffa_version_get")
		.withOutputParameter("major", major)
		.withOutputParameter("minor", minor)
		.returnIntValue();
}

void expect_sp_discovery_own_id_get(const uint16_t *id, sp_result result)
{
	mock()
		.expectOneCall("sp_discovery_own_id_get")
		.withOutputParameterReturning("id", id, sizeof(*id))
		.andReturnValue(result);
}

sp_result sp_discovery_own_id_get(uint16_t *id)
{
	return mock()
		.actualCall("sp_discovery_own_id_get")
		.withOutputParameter("id", id)
		.returnIntValue();
}

void expect_sp_discovery_partition_id_get(const struct sp_uuid *uuid,
					  const uint16_t *id, sp_result result)
{
	mock()
		.expectOneCall("sp_discovery_partition_id_get")
		.withMemoryBufferParameter("uuid", (const unsigned char *)uuid,
					   sizeof(*uuid))
		.withOutputParameterReturning("id", id, sizeof(*id))
		.andReturnValue(result);
}

sp_result sp_discovery_partition_id_get(const struct sp_uuid *uuid,
					uint16_t *id)
{
	return mock()
		.actualCall("sp_discovery_partition_id_get")
		.withMemoryBufferParameter("uuid", (const unsigned char *)uuid,
					   sizeof(*uuid))
		.withOutputParameter("id", id)
		.returnIntValue();
}

void expect_sp_discovery_partition_info_get(const struct sp_uuid *uuid,
					  const struct sp_partition_info *info,
					  uint32_t in_count,
					  const uint32_t *out_count,
					  sp_result result)
{
	mock()
		.expectOneCall("sp_discovery_partition_info_get")
		.withMemoryBufferParameter("uuid", (const unsigned char *)uuid,
					   sizeof(*uuid))
		.withOutputParameterReturning("info", info, sizeof(*info))
		.withUnsignedIntParameter("in_count", in_count)
		.withOutputParameterReturning("out_count", out_count, sizeof(*out_count))
		.andReturnValue(result);
}

sp_result sp_discovery_partition_info_get(const struct sp_uuid *uuid,
					  struct sp_partition_info *info,
					  uint32_t *count)
{
	return mock()
		.actualCall("sp_discovery_partition_info_get")
		.withMemoryBufferParameter("uuid", (const unsigned char *)uuid,
					   sizeof(*uuid))
		.withOutputParameter("info", info)
		.withUnsignedIntParameter("in_count", *count)
		.withOutputParameter("out_count", count)
		.returnIntValue();
}

void expect_sp_discovery_partition_info_get_all(const struct sp_partition_info info[],
						const uint32_t *count,
						sp_result result)
{
	mock()
		.expectOneCall("sp_discovery_partition_info_get_all")
		.withOutputParameterReturning("info", info, sizeof(*info) * *count)
		.withOutputParameterReturning("count", count, sizeof(*count))
		.andReturnValue(result);
}

sp_result sp_discovery_partition_info_get_all(struct sp_partition_info info[],
					      uint32_t *count)
{
	return mock()
		.actualCall("sp_discovery_partition_info_get_all")
		.withOutputParameter("info", info)
		.withOutputParameter("count", count)
		.returnIntValue();
}
