/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2022-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OPENAMP_MESSENGER_API_H
#define OPENAMP_MESSENGER_API_H

#include <stddef.h>
#include <stdint.h>

#include "openamp_messenger.h"

struct openamp_messenger {
	const struct openamp_platform_ops *platform_ops;
	uint32_t ref_count;
	uint8_t status;

	void *transport;
	void *platform;
};

int openamp_messenger_init(struct openamp_messenger *openamp);
void openamp_messenger_deinit(struct openamp_messenger *openamp);
void openamp_messenger_call_end(struct openamp_messenger *openamp);
int openamp_messenger_call_invoke(struct openamp_messenger *openamp,
				  uint8_t **resp_buf, size_t *resp_len);
int openamp_messenger_call_begin(struct openamp_messenger *openamp,
				 uint8_t **req_buf, size_t req_len);

void *openamp_messenger_phys_to_virt(struct openamp_messenger *openamp,
				     void *pa);
void *openamp_messenger_virt_to_phys(struct openamp_messenger *openamp,
				     void *va);
#endif
