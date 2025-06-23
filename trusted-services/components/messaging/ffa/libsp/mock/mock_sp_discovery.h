/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LIBSP_MOCK_MOCK_SP_DISCOVERY_H_
#define LIBSP_MOCK_MOCK_SP_DISCOVERY_H_

#include "../include/sp_discovery.h"

#ifdef __cplusplus
extern "C" {
#endif

void expect_sp_discovery_ffa_version_get(const uint16_t *major,
					 const uint16_t *minor,
					 sp_result result);

void expect_sp_discovery_own_id_get(const uint16_t *id, sp_result result);

void expect_sp_discovery_partition_id_get(const struct sp_uuid *uuid,
					  const uint16_t *id, sp_result result);


void expect_sp_discovery_partition_info_get(const struct sp_uuid *uuid,
					    const struct sp_partition_info *info,
					    uint32_t in_count,
					    const uint32_t *out_count,
					    sp_result result);

void expect_sp_discovery_partition_info_get_all(const struct sp_partition_info info[],
						const uint32_t *count,
						sp_result result);

#ifdef __cplusplus
}
#endif

#endif /* LIBSP_MOCK_MOCK_SP_DISCOVERY_H_ */
