/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef FW_INSPECTOR_H
#define FW_INSPECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct fw_directory;

/**
 * \brief fw_inspector public interface definition
 *
 * A firmware inspector is responsible for retrieving information about the
 * firmware associated with a fw store and refreshing the contents of the
 * presented firmware directory. The information will reflect the state of
 * the firmware at the most recent boot. The method used for discovering information
 * may well vary between device classes and firmware store realizations. To
 * give the necessary flexibility, the fw_inspector 'inspect' function may be
 * realized by alternative implementations. To give the flexibility to
 * combine multiple inspection strategies into a single build (for test or
 * run-time configuration), the inspect method is called via a function pointer.
 *
 * \param[in]  fw_dir      The firmware directory to refresh
 * \param[in]  boot_index  The boot_index reported by the bootloader
 *
 * \return FWU status
 */
typedef int (*fw_inspector_inspect)(struct fw_directory *fw_dir, unsigned int boot_index);

#ifdef __cplusplus
}
#endif

#endif /* FW_INSPECTOR_H */
