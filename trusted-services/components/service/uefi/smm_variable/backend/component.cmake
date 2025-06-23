#-------------------------------------------------------------------------------
# Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/uefi_variable_store.c"
	"${CMAKE_CURRENT_LIST_DIR}/variable_index.c"
	"${CMAKE_CURRENT_LIST_DIR}/variable_index_iterator.c"
	"${CMAKE_CURRENT_LIST_DIR}/variable_checker.c"
	)

set(UEFI_MAX_VARIABLE_SIZE "4096" CACHE STRING "Maximum size of UEFI variables")
target_compile_definitions(${TGT} PRIVATE
	DEFAULT_MAX_VARIABLE_SIZE=${UEFI_MAX_VARIABLE_SIZE}
	)
