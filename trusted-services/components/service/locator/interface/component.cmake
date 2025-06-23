#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

set_property(TARGET ${TGT} APPEND PROPERTY PUBLIC_HEADER
	"${CMAKE_CURRENT_LIST_DIR}/service_locator.h"
	)

target_include_directories(${TGT} PUBLIC
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>"
	"$<INSTALL_INTERFACE:${TS_ENV}/include>"
	)
