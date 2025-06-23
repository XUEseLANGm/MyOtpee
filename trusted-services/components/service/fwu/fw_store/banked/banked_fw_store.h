/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BANKED_FW_STORE_H
#define BANKED_FW_STORE_H

#include <stdint.h>

#include "bank_tracker.h"
#include "metadata_manager.h"
#include "service/fwu/fw_store/fw_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface dependencies
 */
struct installer;
struct metadata_serializer;

/**
 * \brief Banked fw_store structure definition
 *
 * A banked fw_store manages updates to an A/B banked firmware store. The
 * implementation realizes the common fw_store interface. The banked fw_store
 * can handle both Nwd and Swd image installation.
 */
struct fw_store {
	const struct fw_directory *fw_directory;
	struct installer *active_installers;
	struct metadata_manager metadata_manager;
	struct bank_tracker bank_tracker;
	uint32_t update_index;
	uint32_t boot_index;
};

/**
 * \brief Initialize a banked fw_store
 *
 * Initializes a banked fw_store that manages updates according to the Arm
 * FWU-A specification. The provided metadata_serializer should have been
 * selected for compatibility with the bootloader.
 *
 * \param[in]  fw_store       The subject fw_store
 * \param[in]  serializer     The metadata_serializer to use
 *
 * \return FWU status code
 */
int banked_fw_store_init(struct fw_store *fw_store, const struct metadata_serializer *serializer);

/**
 * \brief De-initialize a banked_fw_store
 *
 * \param[in]  fw_store    The subject fw_store
 */
void banked_fw_store_deinit(struct fw_store *fw_store);

#ifdef __cplusplus
}
#endif

#endif /* BANKED_FW_STORE_H */
