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
	"${CMAKE_CURRENT_LIST_DIR}/sfs_flash_fs_dblock.c"
	"${CMAKE_CURRENT_LIST_DIR}/sfs_flash_fs_mblock.c"
	"${CMAKE_CURRENT_LIST_DIR}/sfs_flash_fs.c"
	)

