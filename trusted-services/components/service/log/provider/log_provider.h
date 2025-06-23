/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 */

#ifndef LOG_PROVIDER_H
#define LOG_PROVIDER_H

#include "components/service/common/provider/service_provider.h"
#include "service/log/backend/log_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

struct log_provider {
	struct service_provider base_provider;
	struct log_backend *backend;
};

struct rpc_service_interface *log_provider_init(struct log_provider *context,
						struct log_backend *backend);

#ifdef __cplusplus
}
#endif

#endif /* LOG_PROVIDER_H */
