#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/rpmb_frontend.c"
)

set(RPMB_WRITE_KEY FALSE CACHE BOOL "Enable RPMB Authentication Key Write")

if (RPMB_WRITE_KEY)
set(_RPMB_WRITE_KEY 1)
else()
set(_RPMB_WRITE_KEY 0)
endif()

target_compile_definitions(${TGT} PRIVATE RPMB_WRITE_KEY=${_RPMB_WRITE_KEY})
