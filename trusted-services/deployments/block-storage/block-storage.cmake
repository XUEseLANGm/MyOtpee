#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Common components used for any deployment of the block-storage service
# provider.
#-------------------------------------------------------------------------------

add_components(TARGET "block-storage"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/tlv"
		"components/common/uuid"
		"components/common/endian"
		"components/rpc/common/caller"
		"components/service/common/client"
		"components/service/common/include"
		"components/service/common/provider"
		"components/service/block_storage/block_store"
		"components/service/block_storage/provider"
		"components/service/block_storage/provider/serializer/packed-c"
)

#################################################################

target_include_directories(block-storage PRIVATE
	${TS_ROOT}
	${TS_ROOT}/components
)
