/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OPENAMP_MESSENGER_H
#define OPENAMP_MESSENGER_H

#include <stddef.h>
#include <stdint.h>

struct openamp_messenger;

struct openamp_platform_ops {
	int (*transport_init)(struct openamp_messenger *openamp);
	int (*transport_deinit)(struct openamp_messenger *openamp);
	int (*transport_notify)(struct openamp_messenger *openamp);
	int (*transport_receive)(struct openamp_messenger *openamp);
	int (*platform_init)(struct openamp_messenger *openamp);
	int (*platform_deinit)(struct openamp_messenger *openamp);
	int (*platform_call_begin)(struct openamp_messenger *openamp,
				   uint8_t **req_buf, size_t req_len);
	int (*platform_call_invoke)(struct openamp_messenger *openamp,
				    uint8_t **resp_buf, size_t *resp_len);
	int (*platform_call_end)(struct openamp_messenger *openamp);
	void *(*platform_virt_to_phys)(struct openamp_messenger *openamp,
				       void *va);
	void *(*platform_phys_to_virt)(struct openamp_messenger *openamp,
				       void *pa);
};

#endif
