#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

add_components(TARGET "protected-storage"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		components/common/tlv
		components/service/common/include
		components/service/common/provider
		components/service/common/client
		components/service/secure_storage/include
		components/service/secure_storage/frontend/secure_storage_provider
		components/rpc/common/caller
		protocols/rpc/common/packed-c
		protocols/service/secure_storage/packed-c
)

target_include_directories(protected-storage PRIVATE
	${TS_ROOT}
	${TS_ROOT}/components
)
