#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/restapi_env.c"
	"${CMAKE_CURRENT_LIST_DIR}/restapi_location_strategy.c"
	"${CMAKE_CURRENT_LIST_DIR}/restapi_service_context.c"
	)

# Configurable build parameters
#   TS_CFG_REST_API_SERVICE_URL        URL for reaching services via REST API
#   TS_CFG_REST_API_REACHABLE_TIMEOUT  Timeout in seconds for waiting to reach API
if(DEFINED TS_CFG_REST_API_SERVICE_URL)
	target_compile_definitions(${TGT} PRIVATE
		RESTAPI_LOCATOR_API_URL=${TS_CFG_REST_API_SERVICE_URL})
endif()

if(DEFINED TS_CFG_REST_API_REACHABLE_TIMEOUT)
	target_compile_definitions(${TGT} PRIVATE
		RESTAPI_LOCATOR_MAX_API_WAIT=${TS_CFG_REST_API_REACHABLE_TIMEOUT})
endif()
