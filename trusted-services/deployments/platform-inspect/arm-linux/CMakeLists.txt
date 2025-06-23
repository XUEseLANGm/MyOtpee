#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  Required for use of stdout/stderr file pointers from the application.
#
#-------------------------------------------------------------------------------
set(CMAKE_POSITION_INDEPENDENT_CODE True)

#-------------------------------------------------------------------------------
#  The CMakeLists.txt for building the platform-inspect deployment for arm-linux
#
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/arm-linux/env.cmake)
project(trusted-services LANGUAGES CXX C)
add_executable(platform-inspect)
target_include_directories(platform-inspect PRIVATE "${TOP_LEVEL_INCLUDE_DIRS}")

#-------------------------------------------------------------------------------
#  Extend with components that are common across all deployments of
#  platform-inspect
#
#-------------------------------------------------------------------------------
include(../platform-inspect.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  Define library options and dependencies.
#
#-------------------------------------------------------------------------------
target_link_libraries(platform-inspect PRIVATE stdc++ gcc m)
