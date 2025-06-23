#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Environment file for generic SP deployments. This is a cross-compiled
#  environment where built executables run within secure partitions with
#  standard binary format that can be loaded by any secure partition manager.
#-------------------------------------------------------------------------------
set(TS_ENV "sp" CACHE STRING "Environment identifier")

# Default to using the base toolcahin file for the environment
set(TS_BASE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/default_toolchain_file.cmake" CACHE STRING "Base toolchainfile")

# Replicate in environment variable for access from child cmake contexts
set(ENV{TS_BASE_TOOLCHAIN_FILE} "${TS_BASE_TOOLCHAIN_FILE}")

# Set toolchain files to use
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/default_toolchain_file.cmake" CACHE STRING "Toolchain file")
set(TS_EXTERNAL_LIB_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" CACHE STRING "External lib Toolchain file")
