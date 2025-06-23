#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
# The CMakeLists.txt for building the fwu-tool deployment for linux-pc
#
# This configuration builds the FWU update agent into a command-line app
# that can be used to apply updates to disk image files.
#-------------------------------------------------------------------------------
project(trusted-services LANGUAGES CXX C)
add_executable(fwu-tool)
set(TGT "fwu-tool")
target_include_directories(fwu-tool PRIVATE "${TOP_LEVEL_INCLUDE_DIRS}")

#-------------------------------------------------------------------------------
#  Configure trace output for command-line app
#
#-------------------------------------------------------------------------------
set(TRACE_PREFIX "fwu-tool" CACHE STRING "Trace prefix")
set(TRACE_LEVEL "TRACE_LEVEL_DEBUG" CACHE STRING "Trace level")

#-------------------------------------------------------------------------------
#  Deployment specific build configuration
#
#-------------------------------------------------------------------------------

# Scale number of partitions for pretty complicated fw images
target_compile_definitions(${TGT} PRIVATE
    PARTITIONED_BLOCK_STORE_MAX_PARTITIONS=24)

#-------------------------------------------------------------------------------
# This configuration builds for linux-pc
#
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/linux-pc/env.cmake)
add_components(TARGET ${TGT}
	BASE_DIR ${TS_ROOT}
	COMPONENTS "environments/linux-pc"
)

#-------------------------------------------------------------------------------
#  External project source-level dependencies
#
#-------------------------------------------------------------------------------
include(${TS_ROOT}/external/tf_a/tf-a.cmake)
add_tfa_dependency(TARGET ${TGT})

#-------------------------------------------------------------------------------
#  Deployment specific components
#
#-------------------------------------------------------------------------------
include(../fwu.cmake REQUIRED)
include(../file-block-store.cmake REQUIRED)
