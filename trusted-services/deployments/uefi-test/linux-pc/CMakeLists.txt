#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  The CMakeLists.txt for building the uefi-test deployment for linux-pc
#
#  Used for building and running service level tests in a native PC enviroment.
#  Tests can be run by running the built executable called "uefi-test"
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/linux-pc/env.cmake)
project(trusted-services LANGUAGES CXX C)

# Prevents symbols in the uefi-test executable overriding symbols with
# with same name in libts during dynamic linking performed by the program
# loader.
set(CMAKE_C_VISIBILITY_PRESET hidden)

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
	set(UEFI_TEST_COVERAGE_FILE "uefi-test-coverage.info" CACHE PATH "Path of coverage info file")
	set(UEFI_TEST_COVERAGE_REPORT_DIR "${CMAKE_CURRENT_BINARY_DIR}/uefi-test-coverage-report" CACHE PATH "Directory of coverage report")

	# Collecting coverage
	coverage_generate(
		NAME "uefi-test"
		SOURCE_DIR ${TS_ROOT}
		BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
		OUTPUT_FILE ${COVERAGE_FILE}
	)

	# Filtering project file coverage
	coverage_filter(
		INPUT_FILE ${COVERAGE_FILE}
		OUTPUT_FILE ${UEFI_TEST_COVERAGE_FILE}
		INCLUDE_DIRECTORY ${UNIT_TEST_PROJECT_PATH}/components
	)

	# Coverage report
	coverage_generate_report(
		INPUT_FILE ${UEFI_TEST_COVERAGE_FILE}
		OUTPUT_DIRECTORY ${UEFI_TEST_COVERAGE_REPORT_DIR}
	)
endif()

unit_test_add_suite(
	NAME uefi-test
)

target_include_directories(uefi-test PRIVATE "${TOP_LEVEL_INCLUDE_DIRS}")

#-------------------------------------------------------------------------------
#  Extend with components that are common across all deployments of
#  uefi-test
#
#-------------------------------------------------------------------------------
include(../uefi-test.cmake REQUIRED)
