/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef DIRECT_FW_INSPECTOR_H
#define DIRECT_FW_INSPECTOR_H

#include "service/fwu/inspector/fw_inspector.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief direct_fw_inspector inspect method
 *
 * The concrete inspect method for the direct_fw_inspector. The direct_fw_inspector
 * is a fw_inspector that can be used when direct access to firmware storage volumes
 * is possible e.g. when fw is loaded from Swd flash. The direct_fw_inspector delegates
 * the enumeration of updatable images to the set of installers that were registered
 * with the installer_index as part of the platform configuration.
 *
 * \param[in]  fw_dir      The firmware directory to refresh
 * \param[in]  boot_index  The boot_index reported by the bootloader
 *
 * \return FWU status
 */
int direct_fw_inspector_inspect(struct fw_directory *fw_dir, unsigned int boot_index);

#ifdef __cplusplus
}
#endif

#endif /* DIRECT_FW_INSPECTOR_H */
