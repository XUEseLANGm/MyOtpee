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
	"${CMAKE_CURRENT_LIST_DIR}/crc32.c"
)

if (TS_ENV STREQUAL "arm-linux")
	target_sources(${TGT} PRIVATE
		"${CMAKE_CURRENT_LIST_DIR}/crc32_linux.c"
	)
endif()

if ((TS_ENV STREQUAL "opteesp") OR (TS_ENV STREQUAL "sp"))
	target_sources(${TGT} PRIVATE
		"${CMAKE_CURRENT_LIST_DIR}/crc32_sp.c"
	)
endif()
