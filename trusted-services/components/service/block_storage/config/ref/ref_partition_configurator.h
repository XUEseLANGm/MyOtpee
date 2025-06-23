/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef REF_PARTITION_CONFIGURATOR_H
#define REF_PARTITION_CONFIGURATOR_H

#include <stdbool.h>
#include <service/block_storage/block_store/partitioned/partitioned_block_store.h>
#include <media/disk/guid.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * To support test, a reference storage partition configuration is used with
 * a set of different sized partitions. The total backend block store size
 * is kept as small as possible to allow the reference configuration to be
 * used with a ram backed store in environments where available memory is
 * constrained.
 */

#define REF_PARTITION_BACK_STORE_SIZE   (200)
#define REF_PARTITION_BLOCK_SIZE        (256)

/* About the right size for PSA storage */
#define REF_PARTITION_1_GUID            DISK_GUID_UNIQUE_PARTITION_PSA_ITS
#define REF_PARTITION_1_STARTING_LBA    (0)
#define REF_PARTITION_1_ENDING_LBA      (95)

/* Also about the right size for PSA storage */
#define REF_PARTITION_2_GUID            DISK_GUID_UNIQUE_PARTITION_PSA_PS
#define REF_PARTITION_2_STARTING_LBA    (96)
#define REF_PARTITION_2_ENDING_LBA      (191)

#define REF_PARTITION_3_GUID            DISK_GUID_UNIQUE_PARTITION_PRIMARY_FWU_METADATA
#define REF_PARTITION_3_STARTING_LBA    (192)
#define REF_PARTITION_3_ENDING_LBA      (195)

#define REF_PARTITION_4_GUID            DISK_GUID_UNIQUE_PARTITION_BACKUP_FWU_METADATA
#define REF_PARTITION_4_STARTING_LBA    (196)
#define REF_PARTITION_4_ENDING_LBA      (199)

/**
 * \brief Configures a partitioned_block_store with the reference configuration
 *
 * \param[in]  subject  The subject partitioned_block_store
 */
bool ref_partition_configure(struct partitioned_block_store *subject);

#ifdef __cplusplus
}
#endif

#endif /* REF_PARTITION_CONFIGURATOR_H */
