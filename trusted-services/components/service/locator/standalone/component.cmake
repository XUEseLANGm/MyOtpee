#-------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/standalone_env.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/standalone_service_context.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/standalone_service_registry.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/standalone_location_strategy.cpp"
	)

