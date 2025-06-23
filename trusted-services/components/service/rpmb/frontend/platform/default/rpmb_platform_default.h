/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_PLATFORM_DEFAULT_H_
#define RPMB_PLATFORM_DEFAULT_H_

#include "../../rpmb_frontend.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rpmb_platform_default {
	struct rpmb_platform platform;
};

struct rpmb_platform *rpmb_platform_default_init(struct rpmb_platform_default *context);

void rpmc_platform_default_deinit(struct rpmb_platform_default *context);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_PLATFORM_DEFAULT_H_ */
