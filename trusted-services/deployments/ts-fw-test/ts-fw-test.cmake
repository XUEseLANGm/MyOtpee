#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  The base build file shared between deployments of 'ts-fw-test'. Used for
#  testing the fimware running on a separate DUT, exercised from test cases
#  that run on a host machine. This test configuration is suitable for test
#  scenarios that involve disruptive operations such as device restarts that
#  preclude
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Components that are common across all deployments
#
#-------------------------------------------------------------------------------
add_components(
	TARGET "ts-fw-test"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/endian"
		"components/common/trace"
		"components/common/utils"
		"components/common/uuid"
		"components/rpc/common/interface"
		"components/rpc/common/caller"
		"components/rpc/http/caller"
		"components/rpc/http/caller/test"
		"components/service/common/client"
		"components/service/common/include"
		"components/service/locator"
		"components/service/locator/interface"
		"components/service/locator/remote/restapi"
		"components/service/fwu/test/fwu_client/remote"
		"components/service/fwu/test/fwu_dut"
		"components/service/fwu/test/fwu_dut/proxy"
		"components/service/fwu/test/fwu_dut_factory/remote"
		"components/service/fwu/test/image_directory_checker"
		"components/service/fwu/test/metadata_checker"
		"components/service/fwu/test/metadata_fetcher/client"
)

#-------------------------------------------------------------------------------
#  Installed package dependencies
#
#-------------------------------------------------------------------------------

# Native CURL headers and libraries needed
find_package(CURL REQUIRED)
target_include_directories(ts-fw-test PRIVATE ${CURL_INCLUDE_DIR})
target_link_libraries(ts-fw-test ${CURL_LIBRARIES})

#-------------------------------------------------------------------------------
#  Define install content.
#
#-------------------------------------------------------------------------------
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install CACHE PATH "location to install build output to." FORCE)
endif()
install(TARGETS ts-fw-test RUNTIME DESTINATION ${TS_ENV}/bin)
