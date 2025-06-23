#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/fw_directory.c"
	"${CMAKE_CURRENT_LIST_DIR}/update_agent.c"
	"${CMAKE_CURRENT_LIST_DIR}/stream_manager.c"
	"${CMAKE_CURRENT_LIST_DIR}/img_dir_serializer.c"
	)
