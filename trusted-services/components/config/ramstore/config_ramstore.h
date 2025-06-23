/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * A config store that implements the common config interface that
 * saves configuration data in ram.  This may be used in environments
 * that are configured at run-time e.g. from device tree.  The
 * config_ramstore is a singleton.
 */
#ifndef CONFIG_RAMSTORE_H
#define CONFIG_RAMSTORE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes the singleton store
 *
 */
void config_ramstore_init(void);

/**
 * \brief Clean-up the config_ramstore after use
 */
void config_ramstore_deinit(void);


#ifdef __cplusplus
}
#endif

#endif /* CONFIG_RAMSTORE_H */
