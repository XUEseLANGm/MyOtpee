#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
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
add_components(TARGET "fwu"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/media/disk"
		"components/media/volume"
		"components/media/volume/base_io_dev"
		"components/media/volume/block_volume"
		"components/media/volume/factory/single_flash"
		"components/service/block_storage/block_store"
		"components/service/block_storage/block_store/device"
		"components/service/block_storage/block_store/device/file"
		"components/service/block_storage/block_store/partitioned"
		"components/service/block_storage/factory/file"
		"components/service/block_storage/config/gpt"
)