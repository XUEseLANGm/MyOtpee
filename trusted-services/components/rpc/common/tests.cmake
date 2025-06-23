#
# Copyright (c) 2021, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

include(UnitTest)

unit_test_add_suite(
	NAME mock_rpc_interface
	SOURCES
		${CMAKE_CURRENT_LIST_DIR}/test/mock_rpc_interface.cpp
		${CMAKE_CURRENT_LIST_DIR}/test/test_mock_rpc_interface.cpp
	INCLUDE_DIRECTORIES
		${CMAKE_CURRENT_LIST_DIR}/test
		${UNIT_TEST_PROJECT_PATH}
		${UNIT_TEST_PROJECT_PATH}/components/rpc/common/interface
	COMPILE_DEFINITIONS
		-DARM64
)
