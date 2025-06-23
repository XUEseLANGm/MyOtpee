/*
 * Copyright (c) 2019-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __SECURE_FLASH_STORE_H__
#define __SECURE_FLASH_STORE_H__

#include <service/secure_storage/backend/storage_backend.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sfs_flash_info_t;

/**
 * \brief Initializes the secure flash store backend
 *
 * \param[in] flash_binding Binding to the flash driver
 * \return Pointer to storage backend or NULL on failure
 */
struct storage_backend *sfs_init(const struct sfs_flash_info_t *flash_binding);

#ifdef __cplusplus
}
#endif

#endif /* __SECURE_FLASH_STORE_H__ */
