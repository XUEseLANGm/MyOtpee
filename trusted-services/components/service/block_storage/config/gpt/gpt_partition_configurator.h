/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef GPT_PARTITION_CONFIGURATOR_H
#define GPT_PARTITION_CONFIGURATOR_H

#include <stdbool.h>
#include <common/uuid/uuid.h>
#include <service/block_storage/block_store/block_store.h>
#include <service/block_storage/block_store/partitioned/partitioned_block_store.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Configures a partitioned_block_store using a GPT
 *
 * Loads the GPT (if present) from the firmware volume identified by the
 * specified volume ID and uses it to configure a set of storage partitions.
 *
 * \param[in]  subject    The subject partitioned_block_store to configure
 * \param[in]  volume_id  Identifies the disk volume to read the GPT from
 */
bool gpt_partition_configure(
	struct partitioned_block_store *subject,
	unsigned int volume_id);

#ifdef __cplusplus
}
#endif

#endif /* GPT_PARTITION_CONFIGURATOR_H */
