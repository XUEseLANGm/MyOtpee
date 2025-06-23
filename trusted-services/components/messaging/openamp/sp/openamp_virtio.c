/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 * Copyright (c) 2021-2022, Linaro Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <metal/device.h>
#include <metal/spinlock.h>
#include <openamp/open_amp.h>
#include <platform/interface/device_region.h>
#include <config/interface/config_store.h>

#include <errno.h>
#include <stddef.h>
#include <trace.h>
#include "openamp_messenger_api.h"

#define OPENAMP_SHEM_DEVICE_NAME "openamp-virtio"
#define OPENAMP_RPMSG_ENDPOINT_NAME OPENAMP_SHEM_DEVICE_NAME
#define OPENAMP_RPMSG_ENDPOINT_ADDR 1024

#define OPENAMP_SHEM_PHYS 0x88000000
#define OPENAMP_SHEM_PHYS_PAGES 1
#define OPENAMP_SHEM_SE_PHYS 0xa8000000

#define OPENAMP_SHEM_VDEV_SIZE (4 * 1024)
#define OPENAMP_SHEM_VRING_SIZE (4 * 1024)

#define OPENAMP_BUFFER_NO_WAIT  0
#define OPENAMP_BUFFER_WAIT     1

#define VIRTQUEUE_NR            2
#define VQ_TX                   0
#define VQ_RX                   1

#define VRING_DESCRIPTORS       16
#define VRING_ALIGN             4

#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - (unsigned long)(&((type *)0)->member)))

struct openamp_virtio_shm {
	uintptr_t base_addr;
	size_t size;
	uintptr_t vdev_status;
	size_t vdev_status_size;
	uintptr_t payload_addr;
	size_t payload_size;
	uintptr_t vring_tx;
	size_t vring_tx_size;
	uintptr_t vring_rx;
	size_t vring_rx_size;

	metal_phys_addr_t shm_physmap[OPENAMP_SHEM_PHYS_PAGES];
};

struct openamp_virtio_metal {
	struct metal_spinlock lock;
	struct metal_device shm_dev;
	struct metal_device *io_dev;

	struct metal_io_region *io;
	struct openamp_virtio_shm shm;
};

struct openamp_virtio_device {
	struct virtio_device virtio_dev;
	struct virtqueue *vq[VIRTQUEUE_NR];
	struct virtio_vring_info rvrings[VIRTQUEUE_NR];
};

struct openamp_virtio_rpmsg {
	struct rpmsg_virtio_device rpmsg_vdev;
	struct rpmsg_endpoint ep;
	uint8_t *req_buf;
	uint32_t req_len;
	uint8_t *resp_buf;
	size_t resp_len;
};

struct openamp_virtio {
	struct openamp_messenger *openamp;
	struct openamp_virtio_rpmsg rpmsg;
	struct openamp_virtio_device vdev;
	struct openamp_virtio_metal metal;
};

static struct openamp_virtio *openamp_virtio_from_dev(struct virtio_device *vdev)
{
	struct openamp_virtio_device *openamp_vdev;

	openamp_vdev = container_of(vdev, struct openamp_virtio_device,
			    virtio_dev);

	return container_of(openamp_vdev, struct openamp_virtio, vdev);
}

static struct openamp_virtio_rpmsg *openamp_virtio_rpmsg_from_dev(struct rpmsg_device *rdev)
{
	struct rpmsg_virtio_device *rvdev;

	rvdev = container_of(rdev, struct rpmsg_virtio_device, rdev);

	return container_of(rvdev, struct openamp_virtio_rpmsg, rpmsg_vdev);

}

static void openamp_virtio_metal_device_setup(struct metal_device *shm_dev,
					      struct openamp_virtio_shm *shm)
{
	struct metal_io_region *shm_region;

	shm_region = &shm_dev->regions[0];

	shm_dev->name = OPENAMP_SHEM_DEVICE_NAME;
	shm_dev->num_regions = 1;

	shm_region->virt = (void *)shm->payload_addr;
	shm_region->size = shm->payload_size;

	shm_region->physmap = (metal_phys_addr_t *)&shm->shm_physmap;
	shm_region->page_shift = (metal_phys_addr_t)(-1);
	shm_region->page_mask = (metal_phys_addr_t)(-1);
}

static int openamp_virtio_metal_init(struct openamp_virtio_metal *metal)
{
	struct metal_init_params params = METAL_INIT_DEFAULTS;
	struct metal_device *shm_dev = &metal->shm_dev;
	int ret;

	openamp_virtio_metal_device_setup(shm_dev, &metal->shm);

	metal_spinlock_init(&metal->lock);

	ret = metal_init(&params);
	if (ret < 0)
		return ret;

	ret = metal_register_generic_device(shm_dev);
	if (ret < 0)
		goto metal_finish;

	ret = metal_device_open("generic", OPENAMP_SHEM_DEVICE_NAME,
				&metal->io_dev);
	if (ret < 0)
		goto metal_finish;

	metal->io = metal_device_io_region(metal->io_dev, 0);
	if (!metal->io) {
		EMSG("openamp: virtio: failed to init metal io");
		ret = -EPROTO;
		goto metal_finish;
	}

	return 0;

metal_finish:
	metal_finish();
	return ret;
}

static unsigned char openamp_virtio_status_get(struct virtio_device *vdev)
{
	struct openamp_virtio *virtio = openamp_virtio_from_dev(vdev);
	struct openamp_virtio_shm *shm = &virtio->metal.shm;

	uint32_t status = *(volatile uint32_t *)shm->vdev_status;

	return status;
}

static void openamp_virtio_status_set(struct virtio_device *vdev,
				      unsigned char status)
{
	struct openamp_virtio *virtio = openamp_virtio_from_dev(vdev);
	struct openamp_virtio_shm *shm = &virtio->metal.shm;

	*(volatile uint32_t *)shm->vdev_status = status;
}

static uint32_t openamp_virtio_features_get(struct virtio_device *vdev)
{
	return 1 << VIRTIO_RPMSG_F_NS;
}

static void openamp_virtio_notify(struct virtqueue *vq)
{
	struct openamp_virtio_device *openamp_vdev;
	struct openamp_messenger *openamp;
	struct openamp_virtio *virtio;
	int ret;

	openamp_vdev = container_of(vq->vq_dev, struct openamp_virtio_device, virtio_dev);
	virtio = container_of(openamp_vdev, struct openamp_virtio, vdev);
	openamp = virtio->openamp;

	ret = openamp->platform_ops->transport_notify(openamp);
	if (ret < 0)
		EMSG("openamp: virtio: erro in transport_notify: %d", ret);
}

const static struct virtio_dispatch openamp_virtio_dispatch = {
	.get_status = openamp_virtio_status_get,
	.set_status = openamp_virtio_status_set,
	.get_features = openamp_virtio_features_get,
	.notify = openamp_virtio_notify,
};

static int openamp_virtio_device_setup(struct openamp_virtio *virtio)
{
	struct openamp_virtio_metal *metal = &virtio->metal;
	struct openamp_virtio_device *openamp_vdev = &virtio->vdev;
	struct virtio_device *vdev = &openamp_vdev->virtio_dev;
	struct openamp_virtio_shm *shm = &metal->shm;
	struct virtio_vring_info *rvring;

	rvring = &openamp_vdev->rvrings[0];

	vdev->role = RPMSG_REMOTE;
	vdev->vrings_num = VIRTQUEUE_NR;
	vdev->func = &openamp_virtio_dispatch;

	openamp_vdev->vq[VQ_TX] = virtqueue_allocate(VRING_DESCRIPTORS);
	if (!openamp_vdev->vq[VQ_TX]) {
		EMSG("openamp: virtio: failed to allocate virtqueue 0");
		return -ENOMEM;
	}
	rvring->io = metal->io;
	rvring->info.vaddr = (void *)shm->vring_tx;
	rvring->info.num_descs = VRING_DESCRIPTORS;
	rvring->info.align = VRING_ALIGN;
	rvring->vq = openamp_vdev->vq[VQ_TX];

	openamp_vdev->vq[VQ_RX] = virtqueue_allocate(VRING_DESCRIPTORS);
	if (!openamp_vdev->vq[VQ_RX]) {
		EMSG("openamp: virtio: failed to allocate virtqueue 1");
		goto free_vq;
	}
	rvring = &openamp_vdev->rvrings[VQ_RX];
	rvring->io = metal->io;
	rvring->info.vaddr = (void *)shm->vring_rx;
	rvring->info.num_descs = VRING_DESCRIPTORS;
	rvring->info.align = VRING_ALIGN;
	rvring->vq = openamp_vdev->vq[VQ_RX];

	vdev->vrings_info = &openamp_vdev->rvrings[0];

	return 0;

free_vq:
	virtqueue_free(openamp_vdev->vq[VQ_TX]);
	virtqueue_free(openamp_vdev->vq[VQ_RX]);

	return -ENOMEM;
}

static int openamp_virtio_rpmsg_endpoint_callback(struct rpmsg_endpoint *ep,
						  void *data, size_t len,
						  uint32_t src, void *priv)
{
	struct openamp_virtio_rpmsg *vrpmsg;
	struct rpmsg_device *rdev;

	rdev = ep->rdev;
	vrpmsg = openamp_virtio_rpmsg_from_dev(rdev);

	rpmsg_hold_rx_buffer(ep, data);
	vrpmsg->resp_buf = data;
	vrpmsg->resp_len = len;

	return 0;
}

static void openamp_virtio_rpmsg_service_unbind(struct rpmsg_endpoint *ep)
{
	struct openamp_virtio_rpmsg *vrpmsg;
	struct rpmsg_device *rdev;

	rdev = container_of(ep, struct rpmsg_device, ns_ept);
	vrpmsg = openamp_virtio_rpmsg_from_dev(rdev);

	rpmsg_destroy_ept(&vrpmsg->ep);
}

static void openamp_virtio_rpmsg_endpoint_bind(struct rpmsg_device *rdev,
					       const char *name,
					       unsigned int dest)
{
	struct openamp_virtio_rpmsg *vrpmsg;

	vrpmsg = openamp_virtio_rpmsg_from_dev(rdev);

	rpmsg_create_ept(&vrpmsg->ep, rdev, name, RPMSG_ADDR_ANY, dest,
			 openamp_virtio_rpmsg_endpoint_callback,
			 openamp_virtio_rpmsg_service_unbind);
}

static int openamp_virtio_rpmsg_device_setup(struct openamp_virtio *virtio,
					     struct device_region *virtio_dev)
{
	struct openamp_virtio_rpmsg *vrpmsg = &virtio->rpmsg;
	struct rpmsg_virtio_device *rpmsg_vdev = &vrpmsg->rpmsg_vdev;
	struct openamp_virtio_device *openamp_vdev = &virtio->vdev;
	struct virtio_device *vdev = &openamp_vdev->virtio_dev;
	struct openamp_virtio_metal *metal = &virtio->metal;
	int ret;

	/*
	 * we assume here that we are the client side and do not need to
	 * initialize the share memory poll (this is done at server side).
	 */
	ret = rpmsg_init_vdev(rpmsg_vdev, vdev,
			      openamp_virtio_rpmsg_endpoint_bind, metal->io,
			      NULL);
	if (ret < 0) {
		EMSG("openamp: virtio: init vdev failed: %d", ret);
		return ret;
	}


	ret = rpmsg_create_ept(&vrpmsg->ep, &rpmsg_vdev->rdev,
			       OPENAMP_RPMSG_ENDPOINT_NAME, RPMSG_ADDR_ANY,
			       RPMSG_ADDR_ANY,
			       openamp_virtio_rpmsg_endpoint_callback,
			       openamp_virtio_rpmsg_service_unbind);
	if (ret < 0) {
		EMSG("openamp: virtio: failed to create endpoint: %d", ret);
		return ret;
	}

	/* set default remote addr */
	vrpmsg->ep.dest_addr = OPENAMP_RPMSG_ENDPOINT_ADDR;

	return 0;
}

static void openamp_virtio_shm_set(struct openamp_virtio *virtio,
				   struct device_region *virtio_region)
{
	struct openamp_virtio_shm *shm = &virtio->metal.shm;

	shm->base_addr = virtio_region->base_addr;
	shm->size = virtio_region->io_region_size;

	shm->vdev_status = shm->base_addr;
	shm->vdev_status_size = OPENAMP_SHEM_VDEV_SIZE;

	shm->vring_rx = shm->base_addr + shm->size -
		(2 * OPENAMP_SHEM_VRING_SIZE);
	shm->vring_rx_size = OPENAMP_SHEM_VRING_SIZE;

	shm->vring_tx = shm->vring_rx + shm->vring_rx_size;
	shm->vring_tx_size = OPENAMP_SHEM_VRING_SIZE;

	shm->payload_addr = shm->vdev_status + shm->vdev_status_size;
	shm->payload_size = shm->size - shm->vdev_status_size -
		shm->vring_rx_size - shm->vring_tx_size;

	shm->shm_physmap[0] = OPENAMP_SHEM_PHYS + shm->vdev_status_size;

	IMSG("SHEM: base: 0x%p size: %ld",
	     (void *)shm->base_addr, shm->size);
	IMSG("VDEV: base: 0x%p size: %ld",
	     (void *)shm->vdev_status, shm->vdev_status_size);
	IMSG("PAYLOAD: base: 0x%p size: %ld",
	     (void *)shm->payload_addr, shm->payload_size);
	IMSG("VRING_TX: base: 0x%p size: %ld",
	     (void *)shm->vring_tx, shm->vring_tx_size);
	IMSG("VRING_RX: base: 0x%p size: %ld",
	     (void *)shm->vring_rx, shm->vring_rx_size);
	IMSG("PHYMAP: base: 0x%p", (void *)shm->shm_physmap[0]);
}

static int openamp_virtio_device_get(const char *dev,
				     struct device_region *dev_region)
{
	bool found;

	found = config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION, dev, 0,
				   dev_region, sizeof(*dev_region));
	if (!found) {
		EMSG("openamp: virtio: device region not found: %s", dev);
		return -EINVAL;
	}

	if (dev_region->base_addr == 0 || dev_region->io_region_size == 0) {
		EMSG("openamp: virtio: device region not valid");
		return -EINVAL;
	}

	IMSG("openamp: virtio: device region found: %s addr: 0x%p size: %ld",
	     dev, (void *)dev_region->base_addr, dev_region->io_region_size);

	return  0;
}

int openamp_virtio_call_begin(struct openamp_messenger *openamp, uint8_t **req_buf,
			      size_t req_len)
{
	struct openamp_virtio *virtio = openamp->platform;
	struct openamp_virtio_rpmsg *vrpmsg = &virtio->rpmsg;
	struct rpmsg_endpoint *ep = &vrpmsg->ep;


	*req_buf = rpmsg_get_tx_payload_buffer(ep, &vrpmsg->req_len,
					       OPENAMP_BUFFER_WAIT);
	if (*req_buf == NULL)
		return -EINVAL;

	if (vrpmsg->req_len < req_len)
		return -E2BIG;

	vrpmsg->req_buf = *req_buf;

	return 0;
}

int openamp_virtio_call_invoke(struct openamp_messenger *openamp,
			       uint8_t **resp_buf, size_t *resp_len)
{
	const struct openamp_platform_ops *ops = openamp->platform_ops;
	struct openamp_virtio *virtio = openamp->platform;
	struct openamp_virtio_device *openamp_vdev = &virtio->vdev;
	struct openamp_virtio_rpmsg *vrpmsg = &virtio->rpmsg;
	struct rpmsg_endpoint *ep = &vrpmsg->ep;
	int ret;

	ret = rpmsg_send_nocopy(ep, vrpmsg->req_buf, vrpmsg->req_len);
	if (ret < 0) {
		EMSG("openamp: virtio: send nocopy failed: %d", ret);
		return -EIO;
	}

	if (ret != vrpmsg->req_len) {
		EMSG("openamp: virtio: send less bytes %d than requested %d",
		     ret, vrpmsg->req_len);
		return -EIO;
	}

	if (!ops->transport_receive)
		return 0;

	ret = ops->transport_receive(openamp);
	if (ret < 0) {
		EMSG("openamp: virtio: failed transport_receive");
		return -EIO;
	}

	virtqueue_notification(openamp_vdev->vq[VQ_RX]);

	*resp_buf = vrpmsg->resp_buf;
	*resp_len = vrpmsg->resp_len;

	return  0;
}

void openamp_virtio_call_end(struct openamp_messenger *openamp)
{
	struct openamp_virtio *virtio = openamp->platform;
	struct openamp_virtio_rpmsg *vrpmsg = &virtio->rpmsg;

	rpmsg_release_rx_buffer(&vrpmsg->ep, vrpmsg->resp_buf);

	vrpmsg->req_buf = NULL;
	vrpmsg->req_len = 0;
	vrpmsg->resp_buf = NULL;
	vrpmsg->resp_len = 0;
}

void *openamp_virtio_virt_to_phys(struct openamp_messenger *openamp, void *va)
{
	struct openamp_virtio *virtio = openamp->platform;
	struct openamp_virtio_metal *metal = &virtio->metal;

	return (void *)metal_io_virt_to_phys(metal->io, va);
}

void *openamp_virtio_phys_to_virt(struct openamp_messenger *openamp, void *pa)
{
	struct openamp_virtio *virtio = openamp->platform;
	struct openamp_virtio_metal *metal = &virtio->metal;

	return metal_io_phys_to_virt(metal->io, (metal_phys_addr_t)pa);
}

int openamp_virtio_init(struct openamp_messenger *openamp)
{
	struct device_region virtio_dev;
	struct openamp_virtio *virtio;
	int ret;

	if (openamp->platform)
		return 0;


	virtio = malloc(sizeof(*virtio));
	if (!virtio)
		return -ENOMEM;

	virtio->openamp = openamp;

	ret = openamp_virtio_device_get(OPENAMP_SHEM_DEVICE_NAME, &virtio_dev);
	if (ret < 0)
		goto free_virtio;

	openamp_virtio_shm_set(virtio, &virtio_dev);

	ret = openamp_virtio_metal_init(&virtio->metal);
	if (ret < 0)
		goto free_virtio;

	ret = openamp_virtio_device_setup(virtio);
	if (ret < 0)
		goto finish_metal;

	ret = openamp_virtio_rpmsg_device_setup(virtio, &virtio_dev);
	if (ret < 0) {
		EMSG("openamp: virtio: rpmsg device setup failed: %d", ret);
		goto finish_metal;
	}

	openamp->platform = virtio;

	return 0;

finish_metal:
	metal_finish();

free_virtio:
	free(virtio);

	return ret;
}

int openamp_virtio_deinit(struct openamp_messenger *openamp)
{
	struct openamp_virtio *virtio;

	if (!openamp->platform)
		return 0;

	virtio = openamp->platform;

	metal_finish();
	free(virtio);

	openamp->platform = NULL;

	return 0;
}
