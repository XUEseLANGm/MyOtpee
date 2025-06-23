/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef MOCK_FW_INSPECTOR_H
#define MOCK_FW_INSPECTOR_H

#include "service/fwu/inspector/fw_inspector.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mock image type UUIDs
 */
#define MOCK_IMG_TYPE_UUID_1 "7744b3ab-2672-4a36-b619-b9a3608c9973"
#define MOCK_IMG_TYPE_UUID_2 "52b3b093-08c4-427e-8cfe-a4c3b804ed88"
#define MOCK_IMG_TYPE_UUID_3 "14345e20-a0b6-46dd-8699-e89512596205"
#define MOCK_IMG_TYPE_UUID_4 "420f26dc-0a91-436f-8420-f4372b88ae16"

/**
 * \brief mock_fw_inspector inspect method
 *
 * The concrete inspect method for the mock_fw_inspector. The mock_fw_inspector
 * is a fw_inspector that populates the fw_directory with a fixed set of mock
 * entries. Used for test only.
 *
 * \param[in]  fw_dir      The firmware directory to refresh
 * \param[in]  boot_index  The boot_index reported by the bootloader
 *
 * \return FWU status
 */
int mock_fw_inspector_inspect(struct fw_directory *fw_dir, unsigned int boot_index);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_FW_INSPECTOR_H */
