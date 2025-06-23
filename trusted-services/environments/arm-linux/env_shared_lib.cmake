#-------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Environment file for shared library deployments to linux-pc.
#-------------------------------------------------------------------------------
set(TS_ENV "arm-linux" CACHE STRING "Environment identifier")

if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
	message(FATAL_ERROR "Building shared libraries is not yet working on Windows. Sorry!")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/link_options.cmake)

# Default to using the base toolcahin file for the enviroment
set(TS_BASE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/default_toolchain_file.cmake" CACHE STRING "Base toolchainfile")

# Replicate in environment variable for access from child cmake contexts
set(ENV{TS_BASE_TOOLCHAIN_FILE} "${TS_BASE_TOOLCHAIN_FILE}")

# Set toolchain files to use
set(CMAKE_TOOLCHAIN_FILE "${TS_ROOT}/tools/cmake/compiler/shared_lib_toolchain_file.cmake" CACHE STRING "Toolchain file")
set(TS_EXTERNAL_LIB_TOOLCHAIN_FILE "${TS_ROOT}/tools/cmake/compiler/static_lib_toolchain_file.cmake" CACHE STRING "External lib Toolchain file")
