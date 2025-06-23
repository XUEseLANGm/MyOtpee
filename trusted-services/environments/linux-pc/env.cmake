#-------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Environment file for binary executable deployments to linux-pc.
#-------------------------------------------------------------------------------
set(TS_ENV "linux-pc" CACHE STRING "Environment identifier")

# Default to using the base toolcahin file for the enviroment
set(TS_BASE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/default_toolchain_file.cmake" CACHE STRING "Base toolchain file")

# Replicate in environment variable for access from child cmake contexts
set(ENV{TS_BASE_TOOLCHAIN_FILE} "${TS_BASE_TOOLCHAIN_FILE}")

# Set toolchain files to use
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/default_toolchain_file.cmake" CACHE STRING "Toolchain file")
set(TS_EXTERNAL_LIB_TOOLCHAIN_FILE "${TS_ROOT}/tools/cmake/compiler/static_lib_toolchain_file.cmake" CACHE STRING "External lib Toolchain file")
