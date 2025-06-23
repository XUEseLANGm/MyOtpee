/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OPENAMP_VIRTIO_H
#define OPENAMP_VIRTIO_H

#include <stddef.h>
#include "openamp_messenger_api.h"

int openamp_virtio_call_begin(struct openamp_messenger *openamp,
			      uint8_t **req_buf, size_t req_len);
int openamp_virtio_call_invoke(struct openamp_messenger *openamp,
			       uint8_t **resp_buf, size_t *resp_len);
int openamp_virtio_call_end(struct openamp_messenger *openamp);
void *openamp_virtio_virt_to_phys(struct openamp_messenger *openamp, void *va);
void *openamp_virtio_phys_to_virt(struct openamp_messenger *openamp, void *pa);

int openamp_virtio_init(struct openamp_messenger *openamp);
int openamp_virtio_deinit(struct openamp_messenger *openamp);

#endif
