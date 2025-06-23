#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Test for drivers reused from edk2-platforms
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Components-under-test and test cases edk2 platform tests.
#
#-------------------------------------------------------------------------------
add_components(TARGET "env-test"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/config/test/sp"
)

target_sources(env-test PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/registration/edk2_platform_tests.c
)

#-------------------------------------------------------------------------------
#  This test suite depends on platform specific drivers
#
#-------------------------------------------------------------------------------
add_platform(TARGET "env-test")