/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MEDIA_DISK_GUID_H
#define MEDIA_DISK_GUID_H

/**
 * Some common GUID definitions related to disk object identification used
 * by TS components. This is not intended to be a comprehensive list. Platform
 * integrators are free to define their own GUIDs and to manage them externally.
 */

/* Partition type GUIDs */
#define DISK_GUID_PARTITION_TYPE_FWU_METADATA \
	"8a7a84a0-8387-40f6-ab41-a8b9a5a60d23"

#define DISK_GUID_PARTITION_TYPE_SFS_STORAGE \
	"a495f487-892c-4d9d-b5dc-679a10985aed"

/* Unique partition GUIDs */
#define DISK_GUID_UNIQUE_PARTITION_PRIMARY_FWU_METADATA \
	"c39ef8a6-ec97-4883-aa64-025f40f7d922"

#define DISK_GUID_UNIQUE_PARTITION_BACKUP_FWU_METADATA \
	"c3d82065-58f3-4fcb-a8fc-772434bfc91d"

#define DISK_GUID_UNIQUE_PARTITION_PSA_ITS \
	"92f7d53b-127e-432b-815c-9a95b80d69b7"

#define DISK_GUID_UNIQUE_PARTITION_PSA_PS \
	"701456da-9b50-49b2-9722-47510f851ccd"

#define DISK_GUID_UNIQUE_PARTITION_DISK_HEADER \
	"5cb130b7-a138-4d08-b0be-c2d4eff57870"

#define DISK_GUID_UNIQUE_PARTITION_BOOT_BANK_A \
	"27365ff7-90fe-410b-9fb8-4595fdc27867"

#define DISK_GUID_UNIQUE_PARTITION_BOOT_BANK_B \
	"3a87713e-4b0b-4361-b6d4-019f0ccfe41a"

#endif /* MEDIA_DISK_GUID_H */
