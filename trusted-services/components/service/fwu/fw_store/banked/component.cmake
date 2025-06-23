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
	"${CMAKE_CURRENT_LIST_DIR}/banked_fw_store.c"
	"${CMAKE_CURRENT_LIST_DIR}/metadata_manager.c"
	"${CMAKE_CURRENT_LIST_DIR}/bank_tracker.c"
	)
