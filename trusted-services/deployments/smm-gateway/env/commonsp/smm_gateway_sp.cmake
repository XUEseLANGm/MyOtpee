#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Includes components needed for deploying the smm-gateway within a secure
# partition.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Common components for smm-gateway sp deployments
#
#-------------------------------------------------------------------------------
add_components(TARGET "smm-gateway"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/fdt"
		"components/common/trace"
		"components/common/utils"
		"components/config/ramstore"
		"components/config/loader/sp"
		"components/messaging/ffa/libsp"
		"components/rpc/common/endpoint"
		"components/rpc/ts_rpc/common"
		"components/rpc/ts_rpc/caller/sp"
		"components/rpc/mm_communicate/endpoint/sp"
		"components/service/locator/sp"
		"components/service/locator/sp/ffa"
		"components/service/log/factory"
		"components/service/log/client"
		"components/service/uefi/smm_variable/frontend/mm_communicate"
)

target_sources(smm-gateway PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/smm_gateway_sp.c
	${TS_ROOT}/deployments/smm-gateway/common/smm_gateway.c
)
