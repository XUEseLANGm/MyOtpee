#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Lists components that provide an infrastructure layer for the
# protected-storage service provider that uses the SFS component
# backed by a storage partition provided by the block storage service.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Infrastructure components
#
#-------------------------------------------------------------------------------
add_components(TARGET "protected-storage"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/uuid"
		"components/rpc/common/caller"
		"components/rpc/ts_rpc/caller/sp"
		"components/service/common/client"
		"components/service/locator"
		"components/service/locator/interface"
		"components/service/locator/sp"
		"components/service/locator/sp/ffa"
		"components/service/secure_storage/backend/secure_flash_store"
		"components/service/secure_storage/backend/secure_flash_store/flash_fs"
		"components/service/secure_storage/backend/secure_flash_store/flash"
		"components/service/secure_storage/backend/secure_flash_store/flash/block_store_adapter"
		"components/service/secure_storage/factory/sp/sfs_shared_block_store"
		"components/service/block_storage/block_store"
		"components/service/block_storage/block_store/client"
		"components/service/block_storage/factory/client"
)
