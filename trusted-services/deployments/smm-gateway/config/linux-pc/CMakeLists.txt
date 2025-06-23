#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
include(../../../deployment.cmake REQUIRED)

project(smm-gateway-unit-tests LANGUAGES CXX C)

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
	set(SMM_GATEWAY_COVERAGE_FILE "smm-gateway-coverage.info" CACHE PATH "Path of coverage info file")
	set(SMM_GATEWAY_COVERAGE_REPORT_DIR "${CMAKE_CURRENT_BINARY_DIR}/smm-gateway-coverage-report" CACHE PATH "Directory of coverage report")

	# Collecting coverage
	coverage_generate(
		NAME "smm-gateway unit test"
		SOURCE_DIR ${TS_ROOT}
		BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
		OUTPUT_FILE ${COVERAGE_FILE}
	)

	# Filtering project file coverage
	coverage_filter(
		INPUT_FILE ${COVERAGE_FILE}
		OUTPUT_FILE ${SMM_GATEWAY_COVERAGE_FILE}
		INCLUDE_DIRECTORY ${UNIT_TEST_PROJECT_PATH}/components
	)

	# Coverage report
	coverage_generate_report(
		INPUT_FILE ${SMM_GATEWAY_COVERAGE_FILE}
		OUTPUT_DIRECTORY ${SMM_GATEWAY_COVERAGE_REPORT_DIR}
	)
endif()

include(${TS_ROOT}/components/rpc/common/tests.cmake)
include(${TS_ROOT}/components/rpc/mm_communicate/endpoint/sp/tests.cmake)
include(${TS_ROOT}/components/service/uefi/smm_variable/frontend/mm_communicate/tests.cmake)
