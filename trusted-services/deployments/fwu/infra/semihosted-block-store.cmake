#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# A fwu infrastructure where there is a flash device dedicated to holding
# device firmware and FWU metadata. Flash is assumed to be UEFI formated
# (MBR/GPT) with separate partitions for primary/backup metadata and
# A/B banks for firmware storage. The flash is actually realized by a file
# residing on the host machine and is accessed using semihosting. This
# infrastructure is intended for FVP/Qemu based testing.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  External project source-level dependencies
#
#-------------------------------------------------------------------------------
include(${TS_ROOT}/external/tf_a/tf-a.cmake)
add_tfa_dependency(TARGET "fwu")

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
		"components/service/block_storage/block_store/device/semihosting"
		"components/service/block_storage/block_store/partitioned"
		"components/service/block_storage/factory/semihosting"
		"components/service/block_storage/config/gpt"
)
