/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MM_COMMUNICATE_SERVICE_CONTEXT_H
#define MM_COMMUNICATE_SERVICE_CONTEXT_H

#include <service_locator.h>
#include <protocols/common/efi/efi_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A service_context that represents a service instance located in
 * a partition, accessed using the MM Communicate protocol over
 * FFA.
 */
struct mm_communicate_service_context
{
	struct service_context service_context;
	struct rpc_caller_interface caller;
	uint16_t partition_id;
	EFI_GUID svc_guid;
};

/*
 * Factory method to create a service context associated with the specified
 * partition id and service GUID.
 */
struct mm_communicate_service_context *mm_communicate_service_context_create(
	const char *dev_path,
	uint16_t partition_id,
	const EFI_GUID *svc_guid);

#ifdef __cplusplus
}
#endif

#endif /* MM_COMMUNICATE_SERVICE_CONTEXT_H */
