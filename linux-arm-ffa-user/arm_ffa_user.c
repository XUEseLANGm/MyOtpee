// SPDX-License-Identifier: GPL-2.0-only
/*
 * Thin layer to expose FF-A operations towards user space
 *
 * The FF-A driver operations are currently not accessible from user space. This
 * module creates a debugfs interface to expose them. This is only a temporary
 * workaround, not intended to be merged.
 *
 * Copyright (c) 2020-2023, Arm Limited
 */

#include <linux/arm_ffa.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "arm_ffa_user.h"

/*
 * Warning: this is prototype code, might contain all kinds of errors.
 * Not inteded to be merged, use only for testing purposes.
 */

#define FFA_DEV_CNT_MAX 16

struct shm_desc {
	u64 handle;
	u16 dst_id;
	void *mem_region;
	size_t mem_size;
	struct list_head link;
};

static struct dentry *debugfs_file;
static struct ffa_device_id ffa_user_device_id[FFA_DEV_CNT_MAX] = { };
static struct ffa_device *local_ffa_devs[FFA_DEV_CNT_MAX] = { };
LIST_HEAD(shm);
static char *uuid_str_list[FFA_DEV_CNT_MAX] = { };
static int module_argc = 0;

module_param_array(uuid_str_list, charp, &module_argc, S_IRUSR);
MODULE_PARM_DESC(uuid_str_list, "List of compatible UUIDs");

static int ffa_sync_send_receive(struct ffa_device *dev,
				 struct ffa_send_direct_data *data)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	return ffa_dev_ops_get(dev)->sync_send_receive(dev, data);
#else
	return dev->ops->msg_ops->sync_send_receive(dev, data);
#endif
}

static int ffa_memory_reclaim(struct ffa_device *dev, u64 g_handle, u32 flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	return ffa_dev_ops_get(dev)->memory_reclaim(g_handle, flags);
#else
	return dev->ops->mem_ops->memory_reclaim(g_handle, flags);
#endif
}

static int ffa_memory_share(struct ffa_device *dev,
			    struct ffa_mem_ops_args *args)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	return ffa_dev_ops_get(dev)->memory_share(dev, args);
#else
	return dev->ops->mem_ops->memory_share(args);
#endif
}

static int ffa_user_probe(struct ffa_device *ffa_dev)
{
	size_t n;

	for (n = 0; n < FFA_DEV_CNT_MAX; n++) {
		if (!local_ffa_devs[n]) {
			local_ffa_devs[n] = ffa_dev;
			return 0;
		}
	}

	return -ENOMEM;
}

static void ffa_user_remove(struct ffa_device *ffa_dev)
{
	size_t n;

	for (n = 0; n < FFA_DEV_CNT_MAX; n++) {
		if (local_ffa_devs[n] == ffa_dev) {
			local_ffa_devs[n] = NULL;
			return;
		}
	}
}

static struct ffa_driver ffa_user_driver = {
	.name = "ffa_user",
	.probe = ffa_user_probe,
	.remove = ffa_user_remove,
	.id_table = ffa_user_device_id,
};

static int find_dev_by_id(uint16_t id)
{
	int i;

	for (i = 0; i < FFA_DEV_CNT_MAX; i++) {
		if (local_ffa_devs[i] && local_ffa_devs[i]->vm_id == id)
			return i;
	}

	return -ENODEV;
}

static struct shm_desc *find_shm_by_handle(uint64_t handle)
{
	struct shm_desc *desc;

	list_for_each_entry(desc, &shm, link)
		if (desc->handle == handle)
			return desc;

	return NULL;
}

static int ffa_ioctl_get_part_id(struct ffa_ioctl_ep_desc __user *uargs)
{
	struct ffa_ioctl_ep_desc ep_desc;
	char __user *uuid_uptr;
	char uuid_str[UUID_STRING_LEN + 1];
	uuid_t uuid;
	int i;

	if (copy_from_user(&ep_desc, uargs, sizeof(struct ffa_ioctl_ep_desc)))
		return -EFAULT;

	uuid_uptr = u64_to_user_ptr(ep_desc.uuid_ptr);

	if (copy_from_user(&uuid_str, uuid_uptr, sizeof(uuid_str)))
		return -EFAULT;

	if (uuid_parse(uuid_str, &uuid))
		return -EINVAL;

	for (i = 0; i < FFA_DEV_CNT_MAX; i++) {
		if (local_ffa_devs[i] &&
		    uuid_equal(&uuid, &local_ffa_devs[i]->uuid)) {
			ep_desc.id = (u16)local_ffa_devs[i]->vm_id;
			goto out;
		}
	}

	return -ENODEV;

out:
	if (copy_to_user(uargs, &ep_desc, sizeof(struct ffa_ioctl_ep_desc)))
		return -EFAULT;

	return 0;
}

static int ffa_ioctl_msg_send(struct ffa_ioctl_msg_args __user *uargs)
{
	struct ffa_device *ffa_dev;
	struct ffa_ioctl_msg_args args;
	struct ffa_send_direct_data data;
	int rc, dev_idx;

	if (copy_from_user(&args, uargs, sizeof(struct ffa_ioctl_msg_args)))
		return -EFAULT;

	dev_idx = find_dev_by_id(args.dst_id);
	if (dev_idx < 0)
		return -ENODEV;

	ffa_dev = local_ffa_devs[dev_idx];

	data.data0 = args.args[0];
	data.data1 = args.args[1];
	data.data2 = args.args[2];
	data.data3 = args.args[3];
	data.data4 = args.args[4];

	rc = ffa_sync_send_receive(ffa_dev, &data);
	if (rc)
		return rc;

	args.args[0] = data.data0;
	args.args[1] = data.data1;
	args.args[2] = data.data2;
	args.args[3] = data.data3;
	args.args[4] = data.data4;

	if (copy_to_user(uargs, &args, sizeof(struct ffa_ioctl_msg_args)))
		return -EFAULT;

	return 0;
}

static int ffa_ioctl_shm_init(struct ffa_ioctl_shm_desc __user *uargs)
{
	struct ffa_device *ffa_dev;
	struct ffa_ioctl_shm_desc shm_desc;
	int rc, dev_idx, order, i;
	size_t num_pages;
	struct page **pages;
	struct sg_table sgt;
	struct shm_desc *shm_internal_desc;
	struct ffa_mem_region_attributes mem_attr = {
		.attrs = FFA_MEM_RW,
	};
	struct ffa_mem_ops_args args = {
		.use_txbuf = 1,
		.attrs = &mem_attr,
		.nattrs = 1,
	};

	if (copy_from_user(&shm_desc, uargs, sizeof(struct ffa_ioctl_shm_desc)))
		return -EFAULT;

	dev_idx = find_dev_by_id(shm_desc.dst_id);
	if (dev_idx < 0)
		return -ENODEV;

	ffa_dev = local_ffa_devs[dev_idx];
	mem_attr.receiver = ffa_dev->vm_id;

	shm_internal_desc = kzalloc(sizeof(struct shm_desc), GFP_KERNEL);
	if (!shm_internal_desc)
		return -ENOMEM;

	order = get_order(shm_desc.size);
	num_pages = 1 << order;

	pages = kcalloc(num_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		kfree(shm_internal_desc);
		return -ENOMEM;
	}

	pages[0] = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!pages[0]) {
		kfree(pages);
		kfree(shm_internal_desc);
		return -ENOMEM;
	}

	for (i = 1; i < num_pages; i++)
		pages[i] = pages[i - 1] + 1;

	rc = sg_alloc_table_from_pages(&sgt, pages, num_pages, 0,
				       num_pages * PAGE_SIZE, GFP_KERNEL);
	if (rc) {
		__free_pages(pages[0], order);
		kfree(shm_internal_desc);
		goto out;
	}

	args.sg = sgt.sgl;

	rc = ffa_memory_share(ffa_dev, &args);
	if (rc) {
		__free_pages(pages[0], order);
		kfree(shm_internal_desc);
		goto out;
	}

	shm_desc.handle = args.g_handle;
	shm_desc.size = PAGE_SIZE << order;

	shm_internal_desc->handle = args.g_handle;
	shm_internal_desc->dst_id = ffa_dev->vm_id;
	shm_internal_desc->mem_region = page_address(pages[0]);
	shm_internal_desc->mem_size = PAGE_SIZE << order;

	list_add(&shm_internal_desc->link, &shm);

	if (copy_to_user(uargs, &shm_desc, sizeof(struct ffa_ioctl_shm_desc)))
		rc = -EFAULT;

out:
	sg_free_table(&sgt);
	kfree(pages);
	return rc;
}

static int ffa_ioctl_shm_deinit(struct ffa_ioctl_shm_desc __user *uargs)
{
	struct ffa_device *ffa_dev;
	struct ffa_ioctl_shm_desc shm_desc;
	struct shm_desc *shm_internal_desc;
	int rc, dev_idx;

	if (copy_from_user(&shm_desc, uargs, sizeof(struct ffa_ioctl_shm_desc)))
		return -EFAULT;

	shm_internal_desc = find_shm_by_handle(shm_desc.handle);
	if (!shm_internal_desc)
		return -ENOENT;

	dev_idx = find_dev_by_id(shm_internal_desc->dst_id);
	if (dev_idx < 0)
		return -ENODEV;

	ffa_dev = local_ffa_devs[dev_idx];

	rc = ffa_memory_reclaim(ffa_dev, shm_desc.handle, 0);
	if (rc)
		goto out;

	free_pages((unsigned long)shm_internal_desc->mem_region,
		   get_order(shm_internal_desc->mem_size));

	list_del(&shm_internal_desc->link);
	kfree(shm_internal_desc);

out:
	return rc;
}

static int ffa_ioctl_shm_read(struct ffa_ioctl_buf_desc __user *uargs)
{
	struct ffa_ioctl_buf_desc buf_desc;
	struct shm_desc *shm_internal_desc;
	u8 __user *ubuf;

	if (copy_from_user(&buf_desc, uargs, sizeof(struct ffa_ioctl_buf_desc)))
		return -EFAULT;

	shm_internal_desc = find_shm_by_handle(buf_desc.handle);
	if (!shm_internal_desc)
		return -ENOENT;

	if (buf_desc.buf_len > shm_internal_desc->mem_size)
		return -EINVAL;

	ubuf = u64_to_user_ptr(buf_desc.buf_ptr);

	if (copy_to_user(ubuf, shm_internal_desc->mem_region, buf_desc.buf_len))
		return -EFAULT;

	return 0;
}

static int ffa_ioctl_shm_write(struct ffa_ioctl_buf_desc __user *uargs)
{
	struct ffa_ioctl_buf_desc buf_desc;
	struct shm_desc *shm_internal_desc;
	u8 __user *ubuf;

	if (copy_from_user(&buf_desc, uargs, sizeof(struct ffa_ioctl_buf_desc)))
		return -EFAULT;

	shm_internal_desc = find_shm_by_handle(buf_desc.handle);
	if (!shm_internal_desc)
		return -ENOENT;

	if (buf_desc.buf_len > shm_internal_desc->mem_size)
		return -EINVAL;

	ubuf = u64_to_user_ptr(buf_desc.buf_ptr);

	if (copy_from_user(shm_internal_desc->mem_region, ubuf, buf_desc.buf_len))
		return -EFAULT;

	return 0;
}

static long ffa_user_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case FFA_IOC_GET_PART_ID:
		return ffa_ioctl_get_part_id(uarg);
	case FFA_IOC_MSG_SEND:
		return ffa_ioctl_msg_send(uarg);
	case FFA_IOC_SHM_INIT:
		return ffa_ioctl_shm_init(uarg);
	case FFA_IOC_SHM_DEINIT:
		return ffa_ioctl_shm_deinit(uarg);
	case FFA_IOC_SHM_READ:
		return ffa_ioctl_shm_read(uarg);
	case FFA_IOC_SHM_WRITE:
		return ffa_ioctl_shm_write(uarg);
	default:
		return -EINVAL;
	}
}

static const struct file_operations ffa_user_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ffa_user_ioctl,
};

static void parse_arguments(void)
{
	int i, j;
	uuid_t uuid;

	/* insmod checks if the number of args doesn't exceed the array size */
	for (i = 0; i < module_argc; i++) {
		if (uuid_parse(uuid_str_list[i], &uuid)) {
			pr_warn("Argument %d is not a valid UUID\n", i);
			continue;
		}

		for (j = 0; j < FFA_DEV_CNT_MAX; j++) {
			if (uuid_is_null(&ffa_user_device_id[j].uuid)) {
				ffa_user_device_id[j].uuid = uuid;
				break;
			}
		}
	}
}

static int __init ffa_user_init(void)
{
	parse_arguments();

	debugfs_file = debugfs_create_file("arm_ffa_user", 0644, NULL, NULL,
					   &ffa_user_fops);

	if (IS_ERR_OR_NULL(debugfs_file)) {
		pr_err("failed to create debugfs file");
		return -ENODEV;
	}

	return ffa_register(&ffa_user_driver);
}
module_init(ffa_user_init)

static void __exit ffa_user_exit(void)
{
	ffa_unregister(&ffa_user_driver);
	debugfs_remove(debugfs_file);
	debugfs_file = NULL;
}
module_exit(ffa_user_exit)

MODULE_AUTHOR("Arm");
MODULE_DESCRIPTION("Arm FF-A user space interface");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("5.0.2");
