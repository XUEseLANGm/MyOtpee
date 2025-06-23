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
	"${CMAKE_CURRENT_LIST_DIR}/metadata_checker.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/metadata_checker_v1.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/metadata_checker_v2.cpp"
	)
