#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/installer.c"
	"${CMAKE_CURRENT_LIST_DIR}/installer_index.c"
	)

# Configurable build parameters
# 	TS_CFG_FWU_MAX_INSTALLERS   	Maximum number of installers allowed
#   TS_CFG_FWU_MAX_LOCATIONS		Maximum number of updatable locations
if(DEFINED TS_CFG_FWU_MAX_INSTALLERS)
	target_compile_definitions(${TGT} PRIVATE
		INSTALLER_INDEX_LIMIT=${TS_CFG_FWU_MAX_INSTALLERS})
endif()

if(DEFINED TS_CFG_FWU_MAX_LOCATIONS)
	target_compile_definitions(${TGT} PRIVATE
		INSTALLER_INDEX_LOCATION_ID_LIMIT=${TS_CFG_FWU_MAX_LOCATIONS})
endif()
