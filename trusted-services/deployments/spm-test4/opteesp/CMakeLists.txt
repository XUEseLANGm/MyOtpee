#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
set(TS_PLATFORM "arm/fvp/fvp_base_revc-2xaemv8a" CACHE STRING "Target platform location.")
include(../../deployment.cmake REQUIRED)
include(${TS_ROOT}/environments/opteesp/env.cmake)

project(trusted-services LANGUAGES C ASM)
add_executable(spm-test4)

set(SP_BIN_UUID_CANON "423762ed-7772-406f-99d8-0c27da0abbf8")
set(SP_FFA_UUID_CANON "${SP_BIN_UUID_CANON}")
set(SP_FFA_UUID_CANON "23eb0100-e32a-4497-9052-2f11e584afa6")
set(SP_NUMBER 4)
set(SP_HEAP_SIZE "32 * 1024" CACHE STRING "SP heap size in bytes")
set(SP_BOOT_ORDER "0" CACHE STRING "Boot order of the SP")
set(TRACE_PREFIX "SPM-TEST${SP_NUMBER}" CACHE STRING "Trace prefix")

#-------------------------------------------------------------------------------
#  Components that are spm-test specific to deployment in the opteesp
#  environment.
#-------------------------------------------------------------------------------
add_components(TARGET "spm-test${SP_NUMBER}"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"environments/opteesp"
		"components/common/fdt"
		"components/common/trace"
		"components/common/utils"
		"components/config/ramstore"
		"components/config/loader/sp"
		"components/messaging/ffa/libsp"
)

include(${TS_ROOT}/components/service/spm_test/spm_test.cmake)
