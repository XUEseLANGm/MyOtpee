#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  Configure trace output
#
#-------------------------------------------------------------------------------
set(TRACE_PREFIX "FW_TEST" CACHE STRING "Trace prefix")
set(TRACE_LEVEL "TRACE_LEVEL_DEBUG" CACHE STRING "Trace level")

#-------------------------------------------------------------------------------
#  The CMakeLists.txt for building the ts-fw-test deployment to run as a
#  userspace program in the linux-pc environment.
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/linux-pc/env.cmake)
project(trusted-services LANGUAGES CXX C)

# Preparing firmware-test-build by including it
include(${TS_ROOT}/external/firmware_test_builder/FirmwareTestBuilder.cmake)

include(CTest)
include(UnitTest)

set(COVERAGE FALSE CACHE BOOL "Enable code coverage measurement")
set(UNIT_TEST_PROJECT_PATH ${TS_ROOT} CACHE PATH "Path of the project directory")
set(CMAKE_CXX_STANDARD 11)

unit_test_init_cpputest()

if (COVERAGE)
	include(Coverage)

	set(COVERAGE_FILE "coverage.info")
	set(TS_SERVICE_TEST_COVERAGE_FILE "ts-fw-test-coverage.info" CACHE PATH "Path of coverage info file")
	set(TS_SERVICE_TEST_COVERAGE_REPORT_DIR "${CMAKE_CURRENT_BINARY_DIR}/ts-fw-coverage-report" CACHE PATH "Directory of coverage report")

	# Collecting coverage
	coverage_generate(
		NAME "ts-fw test"
		SOURCE_DIR ${TS_ROOT}
		BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
		OUTPUT_FILE ${COVERAGE_FILE}
	)

	# Filtering project file coverage
	coverage_filter(
		INPUT_FILE ${COVERAGE_FILE}
		OUTPUT_FILE ${TS_SERVICE_TEST_COVERAGE_FILE}
		INCLUDE_DIRECTORY ${UNIT_TEST_PROJECT_PATH}/components
	)

	# Coverage report
	coverage_generate_report(
		INPUT_FILE ${TS_SERVICE_TEST_COVERAGE_FILE}
		OUTPUT_DIRECTORY ${TS_SERVICE_TEST_COVERAGE_REPORT_DIR}
	)
endif()

unit_test_add_suite(
	NAME ts-fw-test
)

target_include_directories(ts-fw-test PRIVATE "${TOP_LEVEL_INCLUDE_DIRS}")

#-------------------------------------------------------------------------------
#  Components that are specific to deployment in the linux-pc environment.
#
#-------------------------------------------------------------------------------
add_components(
	TARGET "ts-fw-test"
	BASE_DIR ${TS_ROOT}
    COMPONENTS
	"environments/posix"
)

#-------------------------------------------------------------------------------
#  Extend with components that are common across all deployments of
#  ts-fw-test
#
#-------------------------------------------------------------------------------
include(../ts-fw-test.cmake REQUIRED)
