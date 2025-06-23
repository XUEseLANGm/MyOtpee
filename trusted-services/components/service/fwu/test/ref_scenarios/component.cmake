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
	"${CMAKE_CURRENT_LIST_DIR}/image_directory_tests.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/invalid_behaviour_tests.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/update_scenario_tests.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/power_failure_tests.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/rollback_tests.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/oversize_image_tests.cpp"
	"${CMAKE_CURRENT_LIST_DIR}/update_fmp_tests.cpp"
	)
