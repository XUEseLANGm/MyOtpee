#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if(NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

include(${TS_ROOT}/external/LinuxFFAUserShim/LinuxFFAUserShim.cmake)

if(NOT MM_COMM_BUFFER_ADDRESS OR NOT MM_COMM_BUFFER_SIZE)
	message(FATAL_ERROR "Address and size of MM comm buffer is not set. Define MM_COMM_BUFFER_ADDRESS "
						"and MM_COMM_BUFFER_SIZE.")
endif()

target_compile_definitions(${TGT} PRIVATE MM_COMM_BUFFER_ADDRESS=${MM_COMM_BUFFER_ADDRESS}
									MM_COMM_BUFFER_SIZE=${MM_COMM_BUFFER_SIZE})

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/mm_communicate_caller.c"
	"${CMAKE_CURRENT_LIST_DIR}/mm_communicate_serializer.c"
	"${CMAKE_CURRENT_LIST_DIR}/carveout.c"
)

target_include_directories(${TGT} PRIVATE
	"${LINUX_FFA_USER_SHIM_INCLUDE_DIR}"
)
