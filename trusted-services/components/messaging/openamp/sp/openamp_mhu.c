/*
 * Copyright (c) 2021-2024, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2023, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <config/interface/config_store.h>
#include <config/interface/config_blob.h>
#include <platform/interface/device_region.h>
#include <platform/drivers/arm/mhu_driver/mhu_v2_x/mhu_v2_x.h>
#include <trace.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include "openamp_messenger_api.h"

#define MHU_V_2_NOTIFY_CHANNEL	0
#define MHU_V_2_NOTIFY_VALUE	0xff

struct openamp_mhu {
	struct device_region rx_region;
	struct device_region tx_region;
	struct mhu_v2_x_dev_t rx_dev;
	struct mhu_v2_x_dev_t tx_dev;
};

static int openamp_mhu_device_get(const char *dev,
				  struct device_region *dev_region)
{
	bool found;

	found = config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION, dev, 0,
				   dev_region, sizeof(*dev_region));
	if (!found)
		return -EINVAL;

	if (!dev_region->base_addr)
		return -EINVAL;

	IMSG("mhu: device region found: %s addr: 0x%p size: %lu", dev,
	     (void *)dev_region->base_addr, dev_region->io_region_size);

	return 0;
}

int openamp_mhu_receive(struct openamp_messenger *openamp)
{
	struct mhu_v2_x_dev_t *rx_dev;
	enum mhu_v2_x_error_t ret;
	struct openamp_mhu *mhu;
	uint32_t channel = 0;
	uint32_t irq_status;

	if (!openamp->transport) {
		EMSG("openamp: mhu: receive transport not initialized");
		return -EINVAL;
	}

	mhu = openamp->transport;
	rx_dev = &mhu->rx_dev;

	irq_status = 0;

	do {
		irq_status = mhu_v2_x_get_interrupt_status(rx_dev);
	} while(!irq_status);

	ret = mhu_v2_1_get_ch_interrupt_num(rx_dev, &channel);
	if (ret < 0)
		return -1;

	ret = mhu_v2_x_channel_clear(rx_dev, channel);
	if (ret != MHU_V_2_X_ERR_NONE) {
		EMSG("openamp: mhu: failed to clear channel: %d", channel);
		return -EPROTO;
	}

	return 0;
}

int openamp_mhu_notify_peer(struct openamp_messenger *openamp)
{
	struct mhu_v2_x_dev_t *tx_dev;
	enum mhu_v2_x_error_t ret;
	struct openamp_mhu *mhu;
	uint32_t access_ready;

	if (!openamp->transport) {
		EMSG("openamp: mhu: notify transport not initialized");
		return -EINVAL;
	}

	mhu = openamp->transport;
	tx_dev = &mhu->tx_dev;

	ret = mhu_v2_x_set_access_request(tx_dev);
	if (ret != MHU_V_2_X_ERR_NONE) {
		EMSG("openamp: mhu: set access request failed");
		return -EPROTO;
	}

	do {
		ret = mhu_v2_x_get_access_ready(tx_dev, &access_ready);
		if (ret != MHU_V_2_X_ERR_NONE) {
			EMSG("openamp: mhu: failed to get access_ready");
			return -EPROTO;
		}
	} while (!access_ready);

	ret = mhu_v2_x_channel_send(tx_dev, MHU_V_2_NOTIFY_CHANNEL,
				    MHU_V_2_NOTIFY_VALUE);
	if (ret != MHU_V_2_X_ERR_NONE) {
		EMSG("openamp: mhu: failed send over channel");
		return -EPROTO;
	}

	ret = mhu_v2_x_reset_access_request(tx_dev);
	if (ret != MHU_V_2_X_ERR_NONE) {
		EMSG("openamp: mhu: failed reset access request");
		return -EPROTO;
	}

	return 0;
}

int openamp_mhu_init(struct openamp_messenger *openamp)
{
	struct mhu_v2_x_dev_t *rx_dev;
	struct mhu_v2_x_dev_t *tx_dev;
	struct openamp_mhu *mhu;
	int ret;

	/* if we already have initialized skip this */
	if (openamp->transport)
		return 0;

	mhu = malloc(sizeof(*mhu));
	if (!mhu)
		return -1;

	ret = openamp_mhu_device_get("mhu-sender", &mhu->tx_region);
	if (ret < 0)
		goto free_mhu;

	ret = openamp_mhu_device_get("mhu-receiver", &mhu->rx_region);
	if (ret < 0)
		goto free_mhu;

	rx_dev = &mhu->rx_dev;
	tx_dev = &mhu->tx_dev;

	rx_dev->base =  mhu->rx_region.base_addr;
	rx_dev->frame = MHU_V2_X_RECEIVER_FRAME;

	tx_dev->base =  mhu->tx_region.base_addr;
	tx_dev->frame = MHU_V2_X_SENDER_FRAME;

	ret = mhu_v2_x_driver_init(rx_dev, MHU_REV_READ_FROM_HW);
	if (ret < 0)
		goto free_mhu;

	ret = mhu_v2_x_driver_init(tx_dev, MHU_REV_READ_FROM_HW);
	if (ret < 0)
		goto free_mhu;

	openamp->transport = (void *)mhu;

	return 0;

free_mhu:
	free(mhu);

	return ret;
}

int openamp_mhu_deinit(struct openamp_messenger *openamp)
{
	struct openamp_mhu *mhu;

	if (!openamp->transport)
		return 0;

	mhu = openamp->transport;
	free(mhu);

	openamp->transport = NULL;

	return 0;
}
