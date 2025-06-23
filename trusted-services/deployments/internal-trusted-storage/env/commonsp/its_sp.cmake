#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Includes components needed for deploying the internal-trusted-storage service provider
# within a secure partition.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Common components for internal-trusted-storage sp deployments
#
#-------------------------------------------------------------------------------
add_components(TARGET "internal-trusted-storage"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/fdt"
		"components/common/trace"
		"components/common/utils"
		"components/config/ramstore"
		"components/config/loader/sp"
		"components/messaging/ffa/libsp"
		"components/rpc/common/endpoint"
		"components/rpc/common/interface"
		"components/rpc/ts_rpc/common"
		"components/rpc/ts_rpc/endpoint/sp"
		"components/rpc/ts_rpc/caller/sp"
		"components/service/log/factory"
		"components/service/log/client"
)

target_sources(internal-trusted-storage PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/its_sp.c
)
