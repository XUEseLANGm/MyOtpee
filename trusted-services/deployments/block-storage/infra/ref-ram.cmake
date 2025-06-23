#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Lists components that provide an infrastructure layer for the block-storage
# service provider that uses a ram-backed block store, partitioned by default
# using the 'ref' configuration. This infrastructure is intended for test
# purposes.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Infrastructure components
#
#-------------------------------------------------------------------------------
add_components(TARGET "block-storage"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/service/block_storage/block_store/device"
		"components/service/block_storage/block_store/device/ram"
		"components/service/block_storage/block_store/partitioned"
		"components/service/block_storage/config/ref"
		"components/service/block_storage/factory/ref_ram"
)
