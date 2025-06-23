#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  The CMakeLists.txt for building the ts-service-test deployment for arm-linux
#
#  Used for building and running service level tests from Linux user-space
#  on an Arm platform with real deployments of trusted services.
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/arm-linux/env.cmake)
project(trusted-services LANGUAGES CXX C)
add_executable(ts-service-test)
target_include_directories(ts-service-test PRIVATE "${TOP_LEVEL_INCLUDE_DIRS}")

add_components(
	TARGET "ts-service-test"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/app/test-runner"
		"components/service/fwu/test/fwu_dut_factory/remote"
 )

include(${TS_ROOT}/external/CppUTest/CppUTest.cmake)
target_link_libraries(ts-service-test PRIVATE CppUTest)

#-------------------------------------------------------------------------------
#  Extend with components that are common across all deployments of
#  ts-service-test
#
#-------------------------------------------------------------------------------
include(../ts-service-test.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  Define library options and dependencies.
#
#-------------------------------------------------------------------------------
target_link_libraries(ts-service-test PRIVATE stdc++ gcc m)
