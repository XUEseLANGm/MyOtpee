#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Includes components needed for deploying the fwu update_agent within a
# Posix environment as a command-line application. Can be used to apply an
# update to a disk image file. Uses the same fwu components as a fw deployment
# of the fwu service.
#-------------------------------------------------------------------------------

if (NOT DEFINED TGT)
	message(FATAL_ERROR "Mandatory parameter TGT is not defined.")
endif()
#-------------------------------------------------------------------------------
# Common components for fwu posix deployments
#
#-------------------------------------------------------------------------------
add_components(TARGET ${TGT}
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/crc32"
		"components/common/trace"
		"components/common/utils"
)

target_sources(${TGT} PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/fwu_main.cpp
	${CMAKE_CURRENT_LIST_DIR}/cmd_update_image.cpp
	${CMAKE_CURRENT_LIST_DIR}/cmd_print_image_dir.cpp
	${CMAKE_CURRENT_LIST_DIR}/cmd_print_metadata_v1.cpp
	${CMAKE_CURRENT_LIST_DIR}/cmd_print_metadata_v2.cpp
	${CMAKE_CURRENT_LIST_DIR}/print_uuid.cpp
	${CMAKE_CURRENT_LIST_DIR}/app/fwu_app.cpp
	${CMAKE_CURRENT_LIST_DIR}/app/metadata_reader.cpp
	${CMAKE_CURRENT_LIST_DIR}/app/metadata_v1_reader.cpp
	${CMAKE_CURRENT_LIST_DIR}/app/metadata_v2_reader.cpp
)