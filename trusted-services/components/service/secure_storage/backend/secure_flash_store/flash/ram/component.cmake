#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

if(DEFINED CFG_SFS_FLASH_AREA_SIZE)
	target_compile_definitions(${TGT} PRIVATE SFS_FLASH_AREA_SIZE=${CFG_SFS_FLASH_AREA_SIZE})
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/sfs_flash_info.c"
	"${CMAKE_CURRENT_LIST_DIR}/sfs_flash_ram.c"
	)
