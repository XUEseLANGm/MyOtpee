/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <stddef.h>
#include <trace.h>
#include "openamp_messenger.h"
#include "openamp_messenger_api.h"
#include "openamp_mhu.h"
#include "openamp_virtio.h"
#include <protocols/rpc/common/packed-c/status.h>

#define OPENAMP_TRANSACTION_IDLE	0x0
#define OPENAMP_TRANSACTION_INPROGRESS	0x1
#define OPENAMP_TRANSACTION_INVOKED	0x2

int openamp_messenger_call_begin(struct openamp_messenger *openamp,
				 uint8_t **req_buf, size_t req_len)
{
	const struct openamp_platform_ops *ops = openamp->platform_ops;
	int ret;

	if (!openamp)
		return -EINVAL;

	ops = openamp->platform_ops;
	if (!req_buf) {
		EMSG("openamp: call_begin: not req_buf");
		return -EINVAL;
	}

	if (req_len > UINT32_MAX || req_len == 0) {
		EMSG("openamp: call_begin: resp_len invalid: %lu", req_len);
		return -EINVAL;
	}

	if (openamp->status != OPENAMP_TRANSACTION_IDLE) {
		EMSG("openamp: call_begin: transaction not idle");
		return -EINVAL;
	}

	ret = ops->platform_call_begin(openamp, req_buf, req_len);
	if (ret < 0) {
		EMSG("openamp: call_begin: platform begin failed: %d", ret);
		return -EINVAL;
	}

	openamp->status = OPENAMP_TRANSACTION_INPROGRESS;

	return 0;
}

int openamp_messenger_call_invoke(struct openamp_messenger *openamp,
				  uint8_t **resp_buf, size_t *resp_len)
{
	const struct openamp_platform_ops *ops;
	int ret;

	if (!openamp || !resp_buf || !resp_len) {
		EMSG("openamp: call_invoke: invalid arguments");
		return -EINVAL;
	}

	if (openamp->status != OPENAMP_TRANSACTION_INPROGRESS) {
		EMSG("openamp: call_invoke: transaction needed to be started");
		return -ENOTCONN;
	}

	ops = openamp->platform_ops;

	ret = ops->platform_call_invoke(openamp, resp_buf, resp_len);
	if (ret < 0)
		return ret;

	openamp->status = OPENAMP_TRANSACTION_INVOKED;

	return 0;
}

void openamp_messenger_call_end(struct openamp_messenger *openamp)
{
	const struct openamp_platform_ops *ops;

	if (!openamp)
		return;

	if (openamp->status == OPENAMP_TRANSACTION_IDLE) {
		EMSG("openamp: call_end: transaction idle");
		return;
	}

	ops = openamp->platform_ops;

	ops->platform_call_end(openamp);

	openamp->status = OPENAMP_TRANSACTION_IDLE;
}

void *openamp_messenger_phys_to_virt(struct openamp_messenger *openamp,
				     void *pa)
{
	const struct openamp_platform_ops *ops = openamp->platform_ops;

	return ops->platform_phys_to_virt(openamp, pa);
}

void *openamp_messenger_virt_to_phys(struct openamp_messenger *openamp,
				     void *va)
{
	const struct openamp_platform_ops *ops = openamp->platform_ops;

	return ops->platform_virt_to_phys(openamp, va);
}

static const struct openamp_platform_ops openamp_virtio_ops = {
	.transport_init = openamp_mhu_init,
	.transport_deinit = openamp_mhu_deinit,
	.transport_notify = openamp_mhu_notify_peer,
	.transport_receive = openamp_mhu_receive,
	.platform_init = openamp_virtio_init,
	.platform_call_begin = openamp_virtio_call_begin,
	.platform_call_invoke = openamp_virtio_call_invoke,
	.platform_call_end = openamp_virtio_call_end,
	.platform_virt_to_phys = openamp_virtio_virt_to_phys,
	.platform_phys_to_virt = openamp_virtio_phys_to_virt,
};

int openamp_messenger_init(struct openamp_messenger *openamp)
{
	const struct openamp_platform_ops *ops;
	int ret;

	if (openamp->ref_count)
		return 0;

	openamp->platform_ops = &openamp_virtio_ops;

	ops = openamp->platform_ops;

	ret = ops->transport_init(openamp);
	if (ret < 0)
		return ret;

	ret = ops->platform_init(openamp);
	if (ret < 0)
		goto denit_transport;

	openamp->ref_count++;

	return 0;

denit_transport:
	ops->transport_deinit(openamp);

	return ret;
}

void openamp_messenger_deinit(struct openamp_messenger *openamp)
{
	if (--openamp->ref_count)
		return;
}
