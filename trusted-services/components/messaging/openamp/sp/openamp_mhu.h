/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2022, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OPENAMP_MHU_H
#define OPENAMP_MHU_H

#include <stddef.h>
#include "openamp_messenger_api.h"

int openamp_mhu_init(struct openamp_messenger *openamp);
int openamp_mhu_deinit(struct openamp_messenger *openamp);

int openamp_mhu_notify_peer(struct openamp_messenger *openamp);
int openamp_mhu_receive(struct openamp_messenger *openamp);

#endif
