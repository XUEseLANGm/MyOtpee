#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

add_components(TARGET "logging"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		components/rpc/common/caller
		components/service/common/include
		components/service/common/client
		components/service/common/provider
		components/service/log/client
		components/service/log/factory
		components/service/log/provider
		components/service/log/backend/uart
		protocols/rpc/common/packed-c
		protocols/service/log/packed-c
)

target_include_directories(logging PRIVATE
	${TS_ROOT}
	${TS_ROOT}/components
)
