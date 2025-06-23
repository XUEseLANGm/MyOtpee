#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../deployment.cmake REQUIRED)

project(libsp-unit-tests LANGUAGES CXX C)

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
	set(LIBSP_COVERAGE_FILE "libsp-coverage.info" CACHE PATH "Path of coverage info file")
	set(LIBSP_COVERAGE_REPORT_DIR "${CMAKE_CURRENT_BINARY_DIR}/libsp-coverage-report" CACHE PATH "Directory of coverage report")

	# Collecting coverage
	coverage_generate(
		NAME "libsp unit test"
		SOURCE_DIR ${TS_ROOT}
		BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
		OUTPUT_FILE ${COVERAGE_FILE}
	)

	# Filtering project file coverage
	coverage_filter(
		INPUT_FILE ${COVERAGE_FILE}
		OUTPUT_FILE ${LIBSP_COVERAGE_FILE}
		INCLUDE_DIRECTORY ${UNIT_TEST_PROJECT_PATH}/components/messaging/ffa/libsp
	)

	# Coverage report
	coverage_generate_report(
		INPUT_FILE ${LIBSP_COVERAGE_FILE}
		OUTPUT_DIRECTORY ${LIBSP_COVERAGE_REPORT_DIR}
	)
endif()

# Including test suite descriptions
include(${TS_ROOT}/components/messaging/ffa/libsp/tests.cmake)
